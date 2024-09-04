import config from 'config';

import {
	AccessDeniedError,
	AuthorizationCode,
	AuthorizeOptions,
	default as OAuthServer,
	InvalidRequestError,
	OAuthError,
	Request as OAuthRequest,
	Response as OAuthResponse,
	ServerOptions,
	UnauthorizedRequestError,
	User,
} from '@node-oauth/oauth2-server';

import { getRedisClient } from '../lib/redis/client.js';
import { client } from '../lib/sql/client.js';
import OAuthModel from './model.js';

import type { Context } from 'koa';
import {
	IntrospectionRequest,
	OAuthRouteOptions,
	PublicAuthorizationCodeDetails,
	RevocationRequest,
} from './types.js';

const serverHost = config.get<string>('server.host');
const dashHost = config.get<string>('server.dashHost');
const docsHost = config.get<string>('server.docsHost');
const directusHost = config.get<string>('server.directusHost');

class ExtendedOAuthServer extends OAuthServer {
	model: OAuthModel;

	constructor (private readonly options: ServerOptions & OAuthRouteOptions) {
		super(options);
		this.model = options.model as OAuthModel;
	}

	override async authorize (request: OAuthRequest, response: OAuthResponse, options?: AuthorizeOptions): Promise<AuthorizationCode> {
		const code = await super.authorize(request, response, options);

		// Interactive approval is required.
		if (code['publicCodeId']) {
			response.redirect(`${this.options.dashHost}/authorize/${code['publicCodeId']}`);
		}

		return code;
	}

	async getApprovalDetails (publicCodeId: string | undefined, response: OAuthResponse): Promise<PublicAuthorizationCodeDetails> {
		if (!publicCodeId) {
			throw new InvalidRequestError('Missing parameter: `publicCodeId`');
		}

		const code = await this.model.getAuthorizationCodeForApproval(publicCodeId);

		if (!code) {
			throw new InvalidRequestError('Invalid parameter: `publicCodeId`');
		}

		response.body = code;
		return code;
	}

	async submitApproval (publicCodeId: string | undefined, approved: boolean, user: User, response: OAuthResponse) {
		if (!publicCodeId) {
			throw new InvalidRequestError('Missing parameter: `publicCodeId`');
		}

		const code = await this.model.approveAuthorizationCode(publicCodeId, approved);

		if (!code) {
			throw new InvalidRequestError('Invalid parameter: `publicCodeId`');
		}

		if (code.user.id !== user['id']) {
			throw new AccessDeniedError('Access denied');
		}

		if (!approved) {
			const url = new URL(code.redirectUri);
			url.search = '';
			url.searchParams.set('error', 'access_denied');
			url.searchParams.set('error_description', 'The user has denied access for your application.');
			code.user.$state && url.searchParams.set('state', code.user.$state);

			return response.redirect(url.href);
		}

		const url = new URL(code.redirectUri);
		url.searchParams.set('code', code.authorizationCode);
		code.user.$state && url.searchParams.set('state', code.user.$state);

		response.redirect(url.href);
	}

	// https://datatracker.ietf.org/doc/html/rfc7662
	async introspect (request: OAuthRequest, response: OAuthResponse) {
		const { token: tokenValue } = request.body as IntrospectionRequest;
		const token = await this.model.getAnyToken(tokenValue);

		if (!token) {
			response.body = {
				active: false,
			};

			return;
		}

		const user = await this.model.getUser(token.user_created);

		response.body = {
			active: true,
			scope: token.scopes.join(' '),
			...token.app_id ? { client_id: token.app_id } : {},
			...user ? { username: user.github_username } : {},
		};
	}

	// https://datatracker.ietf.org/doc/html/rfc7009
	async revoke (request: OAuthRequest) {
		const { token } = request.body as RevocationRequest;
		await this.model.revokeAnyToken(token);
	}

	async handle (ctx: Context, response: OAuthResponse, handler: () => Promise<unknown>) {
		try {
			await handler();
			this.handleResponse(ctx, response);
		} catch (e) {
			this.handleError(ctx, e, response);
		}
	}

	private handleResponse (ctx: Context, response: OAuthResponse) {
		const status = response.status || 500;
		const headers = response.headers || {};

		ctx.set(headers);

		if (status === 302 && headers['location']) {
			ctx.redirect(headers['location']);
		} else {
			ctx.status = status;
			ctx.body = response.body;
		}
	}

	private handleError (ctx: Context, error: unknown, response?: OAuthResponse) {
		if (!(error instanceof OAuthError) || error.code >= 500) {
			throw error;
		}

		ctx.set(response?.headers || {});
		ctx.status = error.code;

		if (error instanceof UnauthorizedRequestError) {
			return;
		}

		if (response?.headers?.['location']) {
			return ctx.redirect(response.headers['location']);
		}

		ctx.body = {
			error: error.name,
			error_description: error.message,
		};
	}
}

export const oAuthModel = new OAuthModel(getRedisClient(), client);

export const oAuthServerOptions = {
	model: oAuthModel,
	allowEmptyState: true, // We require PKCE for all clients so using state is not necessary.
	dashHost,
	docsHost,
	serverHost,
	directusHost,
};

export const oAuthServer = new ExtendedOAuthServer(oAuthServerOptions);

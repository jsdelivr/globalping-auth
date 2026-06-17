import { Response as OAuthResponse } from '@node-oauth/oauth2-server';
import { oAuthServer } from '../server.js';
import { ExtendedContext } from '../../types.js';
import { OAuthRouteOptions } from '../types.js';
import { createOAuthRequest } from '../request.js';

type StateObject = { state?: string } | undefined;

const handle = (options: OAuthRouteOptions) => {
	return async (ctx: ExtendedContext): Promise<void> => {
		if (!ctx.state.user || ctx.state.user.authMode !== 'cookie') {
			return ctx.redirect(`${options.directusHost}/auth/login/github?redirect=${encodeURIComponent(`/redirect?url=${encodeURIComponent(`${options.serverHost}${ctx.url}`)}`)}`);
		}

		const user = ctx.state.user;
		const request = createOAuthRequest(ctx);
		const response = new OAuthResponse(ctx.response);
		const state = (request.body as StateObject)?.state || (request.query as StateObject)?.state;

		await oAuthServer.handle(ctx, response, () => {
			return oAuthServer.authorize(request, response, {
				authenticateHandler: {
					handle () {
						return {
							id: user.id,
							$state: state || null,
						};
					},
				},
			});
		});
	};
};

export const authorizeGet = handle;
export const authorizePost = handle;

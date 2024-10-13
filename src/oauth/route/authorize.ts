import { Request as OAuthRequest, Response as OAuthResponse } from '@node-oauth/oauth2-server';
import { oAuthServer } from '../server.js';
import type { ExtendedContext } from '../../types.js';
import type { OAuthRouteOptions } from '../types.js';

type StateObject = { state?: string } | undefined;

const handle = (options: OAuthRouteOptions) => {
	return async (ctx: ExtendedContext): Promise<void> => {
		if (!ctx.state.user || ctx.state.user.authMode !== 'cookie') {
			return ctx.redirect(`${options.directusHost}/auth/login/github?redirect=${encodeURIComponent(`/redirect?url=${encodeURIComponent(`${options.serverHost}${ctx.url}`)}`)}`);
		}

		const user = ctx.state.user;
		const state = (ctx.request.body as StateObject)?.state || (ctx.query as StateObject)?.state;
		const request = new OAuthRequest(ctx.request);
		const response = new OAuthResponse(ctx.response);

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

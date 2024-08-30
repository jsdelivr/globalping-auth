import { Request as OAuthRequest, Response as OAuthResponse } from '@node-oauth/oauth2-server';
import { oAuthServer } from '../server.js';
import type { ExtendedContext } from '../../types.js';

export const tokenPost = () => {
	return async (ctx: ExtendedContext): Promise<void> => {
		const request = new OAuthRequest(ctx.request);
		const response = new OAuthResponse(ctx.response);

		await oAuthServer.handle(ctx, response, () => {
			return oAuthServer.token(request, response, {
				accessTokenLifetime: 24 * 60 * 60,
				refreshTokenLifetime: 14 * 24 * 60 * 60,
				requireClientAuthentication: {
					refresh_token: false,
				},
			});
		});
	};
};

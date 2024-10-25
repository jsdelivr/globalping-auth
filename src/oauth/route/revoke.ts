import { oAuthServer } from '../server.js';
import { ExtendedContext } from '../../types.js';
import { Request as OAuthRequest, Response as OAuthResponse } from '@node-oauth/oauth2-server';

export const revokePost = () => {
	return async (ctx: ExtendedContext): Promise<void> => {
		const request = new OAuthRequest(ctx.request);
		const response = new OAuthResponse(ctx.response);

		await oAuthServer.handle(ctx, response, () => {
			return oAuthServer.revoke(request);
		});
	};
};

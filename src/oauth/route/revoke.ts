import { oAuthServer } from '../server.js';
import { ExtendedContext } from '../../types.js';
import { Response as OAuthResponse } from '@node-oauth/oauth2-server';
import { createOAuthRequest } from '../request.js';

export const revokePost = () => {
	return async (ctx: ExtendedContext): Promise<void> => {
		const request = createOAuthRequest(ctx);
		const response = new OAuthResponse(ctx.response);

		await oAuthServer.handle(ctx, response, () => {
			return oAuthServer.revoke(request);
		});
	};
};

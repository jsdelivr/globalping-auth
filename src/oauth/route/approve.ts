import { Response as OAuthResponse } from '@node-oauth/oauth2-server';
import { oAuthServer } from '../server.js';
import { ExtendedContext } from '../../types.js';
import { ApproveRequest } from '../types.js';

export const approveGet = async (ctx: ExtendedContext): Promise<void> => {
	const publicCodeId = ctx.params['publicCodeId'];
	const response = new OAuthResponse(ctx.response);

	await oAuthServer.handle(ctx, response, () => {
		return oAuthServer.getApprovalDetails(publicCodeId, response);
	});
};

export const approvePost = async (ctx: ExtendedContext): Promise<void> => {
	if (!ctx.state.user || ctx.state.user.authMode !== 'cookie') {
		ctx.status = 401;
		return;
	}

	const user = ctx.state.user;
	const publicCodeId = ctx.params['publicCodeId'];
	const { approved } = ctx.request.body as ApproveRequest;
	const response = new OAuthResponse(ctx.response);

	await oAuthServer.handle(ctx, response, () => {
		return oAuthServer.submitApproval(publicCodeId, !!approved, user, response);
	});
};



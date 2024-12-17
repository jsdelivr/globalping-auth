import config from 'config';
import { jwtVerify } from 'jose';
import apmAgent from 'elastic-apm-node';

import { ExtendedMiddleware } from '../../../types.js';

const sessionConfig = config.get<AuthenticateOptions['session']>('server.session');

type SessionCookiePayload = {
	id?: string;
	role?: string;
	app_access?: number;
	admin_access?: number;
};

export const authenticate = (): ExtendedMiddleware => {
	const sessionKey = Buffer.from(sessionConfig.cookieSecret);

	return async (ctx, next) => {
		const sessionCookie = ctx.cookies.get(sessionConfig.cookieName);

		if (sessionCookie) {
			try {
				const result = await jwtVerify<SessionCookiePayload>(sessionCookie, sessionKey);

				if (result.payload.id && result.payload.app_access) {
					ctx.state.user = { id: result.payload.id, authMode: 'cookie' };
					apmAgent.setUserContext({ id: result.payload.id });
				}
			} catch {}
		}

		return next();
	};
};

export type AuthenticateOptions = { session: { cookieName: string, cookieSecret: string } };
export type AuthenticateState = { user?: { id: string, scopes?: string[], authMode: 'cookie' | 'token' } };

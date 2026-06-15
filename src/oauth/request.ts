import { Request as OAuthRequest } from '@node-oauth/oauth2-server';
import { ExtendedContext } from '../types.js';

const normalizeHeaders = (headers: ExtendedContext['headers']): Record<string, string> => {
	return Object.fromEntries(Object.entries(headers).flatMap(([ key, value ]) => {
		if (value === undefined) {
			return [];
		}

		return [ [ key, Array.isArray(value) ? value.join(', ') : value ] ];
	}));
};

const normalizeQuery = (query: ExtendedContext['query']): Record<string, string> => {
	return Object.fromEntries(Object.entries(query).flatMap(([ key, value ]) => {
		if (value === undefined) {
			return [];
		}

		return [ [ key, Array.isArray(value) ? value[0] ?? '' : value ] ];
	}));
};

export const createOAuthRequest = (ctx: ExtendedContext): OAuthRequest => {
	return new OAuthRequest({
		headers: normalizeHeaders(ctx.headers),
		method: ctx.method,
		query: normalizeQuery(ctx.query),
		body: ctx.request.body,
	});
};

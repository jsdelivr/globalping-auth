import config from 'config';
import { ExtendedContext } from '../../types.js';
import { OAuthRouteOptions } from '../types.js';

export const metadataGet = (options: OAuthRouteOptions) => {
	return async (ctx: ExtendedContext): Promise<void> => {
		ctx.body = {
			issuer: `${options.serverHost}`,
			authorization_endpoint: `${options.serverHost}/oauth/authorize`,
			token_endpoint: `${options.serverHost}/oauth/token`,
			introspection_endpoint: `${options.serverHost}/oauth/token/introspect`,
			revocation_endpoint: `${options.serverHost}/oauth/token/revoke`,
			scopes_supported: config.get<string[]>('auth.validScopes'),
			response_types_supported: [
				'code',
				'token',
			],
			response_modes_supported: [
				'query',
			],
			grant_types_supported: [
				'authorization_code',
				'client_credentials',
				'refresh_token',
			],
			token_endpoint_auth_methods_supported: [
				'client_secret_basic',
				'client_secret_post',
			],
			service_documentation: `${options.docsHost}/docs/api.globalping.io`,
			code_challenge_methods_supported: [
				'S256',
			],
		};
	};
};

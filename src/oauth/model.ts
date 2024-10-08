import config from 'config';
import { promisify } from 'node:util';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { base32 } from '@scure/base';
import _ from 'lodash';

import {
	AuthorizationCode,
	AuthorizationCodeModel,
	InvalidClientError,
	InvalidRequestError,
	RefreshToken,
	RefreshTokenModel,
	Token as TokenWithClientUser,
} from '@node-oauth/oauth2-server';

import type { Knex } from 'knex';
import type { RedisClient } from '../lib/redis/shared.js';

import {
	AuthorizationCodeSaved,
	AuthorizationCodeToSave,
	ClientRow,
	ClientWithCredentials,
	InternalToken,
	InternalTokenRow,
	InternalUser,
	PublicAuthorizationCodeDetails,
	Token,
	User,
	type Approval,
} from './types.js';

const getRandomBytes = promisify(randomBytes);

export default class OAuthModel implements AuthorizationCodeModel, RefreshTokenModel {
	static appsTable = 'gp_apps';
	static appsAprovalsTable = 'gp_apps_approvals';
	static usersTable = 'directus_users';
	static tokensTable = 'gp_tokens';
	static validScopes = config.get<string[]>('auth.validScopes');

	constructor (
		private readonly redis: RedisClient,
		private readonly sql: Knex,
	) {}

	async generateAccessToken (): Promise<string> {
		const bytes = await getRandomBytes(20);
		return base32.encode(bytes).toLowerCase();
	}

	async generateRefreshToken (): Promise<string> {
		return this.generateAccessToken();
	}

	async getAccessToken (): Promise<null> {
		throw new Error('Method not implemented.');
	}

	async getRefreshToken (refreshToken: string): Promise<RefreshToken | null> {
		const token = await this.getAnyToken(refreshToken);

		if (!token || !token.app_id) {
			return null;
		}

		const client = await this.getClient(token.app_id, null);

		if (!client) {
			return null;
		}

		return {
			client,
			refreshToken,
			scope: token.scopes,
			user: { id: token.user_created },
			...token.expire ? { refreshTokenExpiresAt: token.expire } : {},
		};
	}

	async getAnyToken (tokenValue: string): Promise<InternalToken | null> {
		const bytes = this.decodeToken(tokenValue);

		if (!bytes) {
			return null;
		}

		const hash = createHash('sha256').update(bytes).digest('base64');
		const token = await this.sql(OAuthModel.tokensTable)
			.where({ value: hash })
			.first<InternalTokenRow>();

		if (!token) {
			return null;
		}

		return {
			id: token.id,
			type: token.type,
			name: token.name,
			value: token.value,
			scopes: JSON.parse(token.scopes) as string[],
			origins: JSON.parse(token.origins) as string[],
			expire: token.expire,
			date_last_used: token.date_last_used,
			app_id: token.app_id,
			parent: token.parent,
			user_created: token.user_created,
		};
	}

	async getAuthorizationCode (authorizationCode: string): Promise<AuthorizationCode | null> {
		const key = this.getApprovedAuthorizationCodeRedisKey(authorizationCode);
		const code = await this.redis.json.get(key) as AuthorizationCodeSaved | null;

		if (!code) {
			return null;
		}

		const client = await this.getClient(code.client.id, null);

		if (!client) {
			return null;
		}

		return {
			...code,
			expiresAt: new Date(code.expiresAt),
			client,
		};
	}

	async getAuthorizationCodeForApproval (publicCodeId: string): Promise<PublicAuthorizationCodeDetails | null> {
		const key = this.getPendingAuthorizationCodeRedisKey(publicCodeId);
		const code = await this.redis.json.get(key) as AuthorizationCodeSaved | null;

		if (!code) {
			return null;
		}

		return {
			scope: code.scope || [],
			client: code.client,
		};
	}

	async approveAuthorizationCode (publicCodeId: string, approved: boolean): Promise<AuthorizationCodeSaved | null> {
		const oldKey = this.getPendingAuthorizationCodeRedisKey(publicCodeId);
		const code = await this.redis.json.get(oldKey) as AuthorizationCodeSaved | null;

		if (!code) {
			return null;
		}

		if (!approved) {
			await this.redis.del(oldKey);
			return code;
		}

		if (code.rememberApproval) {
			await this.sql(OAuthModel.appsAprovalsTable).upsert({
				id: randomUUID(),
				user: code.user.id,
				app: code.client.id,
				scopes: JSON.stringify(code.scopesToApprove),
			});
		}

		const newKey = this.getApprovedAuthorizationCodeRedisKey(code.authorizationCode);
		await this.redis.rename(oldKey, newKey);

		return code;
	}

	async saveAuthorizationCode (code: AuthorizationCodeToSave, client: ClientWithCredentials, user: User): Promise<AuthorizationCode | null> {
		// Require PKCE: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics-29#section-2.1.1
		if (!code.codeChallenge) {
			throw new InvalidRequestError('Missing parameter: `codeChallenge`');
		}

		let isApprovalRequired = true;
		let rememberApproval = false;
		let scopesToApprove: string[] = [];

		if (client.secrets.length > 0) {
			rememberApproval = true;
			scopesToApprove = code.scope ?? [];
			const approval = await this.sql(OAuthModel.appsAprovalsTable).where({ user: user.id, app: client.id }).select<Approval>([ 'scopes' ]).first() || null;

			if (approval) {
				const approvedScopes = JSON.parse(approval.scopes) as string[];

				if (code.scope && code.scope.every(s => approvedScopes.includes(s))) {
					isApprovalRequired = false;
				} else {
					scopesToApprove = _.union(approvedScopes, code.scope);
				}
			}
		}

		const codeToSave = code as AuthorizationCode;
		let key;

		if (!isApprovalRequired) {
			key = this.getApprovedAuthorizationCodeRedisKey(codeToSave.authorizationCode);
		} else {
			codeToSave['publicCodeId'] = await this.generateAccessToken();
			codeToSave['rememberApproval'] = rememberApproval;
			codeToSave['scopesToApprove'] = scopesToApprove;
			key = this.getPendingAuthorizationCodeRedisKey(codeToSave['publicCodeId'] as string);
		}

		await Promise.all([
			this.redis.json.set(key, '$', {
				...codeToSave,
				client: { id: client.id, name: client.name, owner: { name: client.owner_name, url: client.owner_url } },
				user: { id: user.id, $state: user.$state },
			}),
			this.redis.pExpireAt(key, codeToSave.expiresAt),
		]);

		return {
			...codeToSave,
			client,
			user,
		};
	}

	async revokeAuthorizationCode (code: AuthorizationCode): Promise<boolean> {
		const key = this.getApprovedAuthorizationCodeRedisKey(code.authorizationCode);
		const keysDeleted = await this.redis.del(key);

		return keysDeleted === 1;
	}

	async getClient (clientId: string, clientSecret: string | null): Promise<ClientWithCredentials> {
		const row = await this.sql(OAuthModel.appsTable).where({ id: clientId }).first<ClientRow>();

		if (!row) {
			throw new InvalidClientError('Invalid client: client is invalid');
		}

		const client: ClientWithCredentials = {
			id: row.id,
			name: row.name,
			secrets: JSON.parse(row.secrets) as string[],
			owner_name: row.owner_name,
			owner_url: row.owner_url,
			requestSecret: null,
			redirectUris: JSON.parse(row.redirect_urls) as string[],
			grants: JSON.parse(row.grants) as string[],
			...row.access_token_lifetime ? { accessTokenLifetime: row.access_token_lifetime } : {},
			...row.refresh_token_lifetime ? { refreshTokenLifetime: row.refresh_token_lifetime } : {},
		};

		if (client.secrets.length > 0 && clientSecret) {
			let requestSecret;

			try {
				const bytes = base32.decode(clientSecret.toUpperCase());
				requestSecret = createHash('sha256').update(bytes).digest('base64');
			} catch {
				requestSecret = null;
			}

			if (!requestSecret || !client.secrets.includes(requestSecret)) {
				throw new InvalidClientError('Invalid client: client credentials are invalid');
			}

			client.requestSecret = requestSecret;
		}

		return client;
	}

	async getUser (id: string): Promise<InternalUser | null> {
		return await this.sql(OAuthModel.usersTable).where({ id }).select<InternalUser>([ 'id', 'github_username' ]).first() || null;
	}

	async revokeToken (token: RefreshToken): Promise<boolean> {
		return this.revokeAnyToken(token.refreshToken, 'refresh_token');
	}

	async revokeAnyToken (tokenValue: string, type?: string): Promise<boolean> {
		const token = await this.getAnyToken(tokenValue);
		let rowsDeleted = 0;

		if (!token || (type && token.type !== type)) {
			return false;
		}

		rowsDeleted += await this.sql(OAuthModel.tokensTable).where({ parent: token.id }).delete();
		rowsDeleted += await this.sql(OAuthModel.tokensTable).where({ value: token.value }).delete();

		return rowsDeleted > 0;
	}

	async saveToken (token: Token, client: ClientWithCredentials, user: User): Promise<TokenWithClientUser | null> {
		const now = new Date();
		let refreshTokenId;

		if (client.secrets.length > 0 && (!client.requestSecret || !client.secrets.includes(client.requestSecret))) {
			throw new InvalidClientError('Invalid client: client credentials are invalid');
		}

		if (token.refreshToken) {
			const refreshBytes = base32.decode(token.refreshToken.toUpperCase());
			const refreshHash = createHash('sha256').update(refreshBytes).digest('base64');

			[ refreshTokenId ] = await this.sql(OAuthModel.tokensTable).insert({
				type: 'refresh_token',
				name: `For ${client.name}`,
				scopes: JSON.stringify(token.scope || []),
				expire: token.refreshTokenExpiresAt,
				date_created: now,
				user_created: user.id,
				app_id: client.id,
				value: refreshHash,
			});
		}

		const accessBytes = base32.decode(token.accessToken.toUpperCase());
		const accessHash = createHash('sha256').update(accessBytes).digest('base64');

		await this.sql(OAuthModel.tokensTable).insert({
			type: 'access_token',
			name: `For ${client.name}`,
			scopes: JSON.stringify(token.scope || []),
			expire: token.accessTokenExpiresAt,
			date_created: now,
			user_created: user.id,
			app_id: client.id,
			value: accessHash,
			parent: refreshTokenId,
		});

		return {
			...token,
			client,
			user,
		};
	}

	async validateScope (_user: User, _client: ClientWithCredentials, scope?: string[]): Promise<string[] | null> {
		if (!scope || !scope.every(s => OAuthModel.validScopes.includes(s))) {
			return null;
		}

		return scope;
	}

	private getApprovedAuthorizationCodeRedisKey (authorizationCode: string): string {
		return `oauth:aac:${authorizationCode}`;
	}

	private getPendingAuthorizationCodeRedisKey (authorizationCode: string): string {
		return `oauth:pac:${authorizationCode}`;
	}

	private decodeToken (token: string): Uint8Array | null {
		try {
			return base32.decode(token.toUpperCase());
		} catch {
			return null;
		}
	}
}

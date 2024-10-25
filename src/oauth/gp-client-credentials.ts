import {
	AbstractGrantType,
	InvalidArgumentError,
	InvalidGrantError,
	type Request,
} from '@node-oauth/oauth2-server';
import type { ClientCredentialsUser, ClientWithCredentials, GrantTypeOptions, User } from './types.js';
import type OAuthModel from './model.js';

export default class GPClientCredentials extends AbstractGrantType {
	model: OAuthModel;

	constructor (options: GrantTypeOptions = {}) {
		if (!options.model) {
			throw new InvalidArgumentError('Missing parameter: `model`');
		}

		if (!options.model.getUserFromClient) {
			throw new InvalidArgumentError('Invalid argument: model does not implement `getUserFromClient()`');
		}

		if (!options.model.saveToken) {
			throw new InvalidArgumentError('Invalid argument: model does not implement `saveToken()`');
		}

		super(options);
		this.model = options.model;
	}

	async handle (request: Request, client: ClientWithCredentials) {
		if (!request) {
			throw new InvalidArgumentError('Missing parameter: `request`');
		}

		if (!client) {
			throw new InvalidArgumentError('Missing parameter: `client`');
		}

		const scope = this.getScope(request);
		const user = await this.getUserFromClient(client);

		return this.saveToken(user, client, scope);
	}

	async getUserFromClient (client: ClientWithCredentials) {
		const user = await this.model.getUserFromClient(client);

		if (!user) {
			throw new InvalidGrantError('Invalid grant: user credentials are invalid');
		}

		return user;
	}

	async saveToken (user: ClientCredentialsUser, client: ClientWithCredentials, requestedScope: string[]) {
		const validatedScope = await this.validateScope(user, client, requestedScope) as string[];
		const accessToken = await this.generateAccessToken(client, user, validatedScope);
		const refreshToken = await this.generateRefreshToken(client, user, validatedScope);
		const accessTokenExpiresAt = this.getAccessTokenExpiresAt();
		const refreshTokenExpiresAt = this.getRefreshTokenExpiresAt();

		const token = {
			accessToken,
			accessTokenExpiresAt,
			refreshToken,
			refreshTokenExpiresAt,
			scope: validatedScope,
		};

		return this.model.saveToken(token, client, user as unknown as User);
	}
}

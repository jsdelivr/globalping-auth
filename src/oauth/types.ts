import { AuthorizationCode, Client, Token as TokenWithClientUser } from '@node-oauth/oauth2-server';

export type AuthorizationCodeToSave = Pick<AuthorizationCode, 'authorizationCode' | 'expiresAt' | 'redirectUri' | 'scope' | 'codeChallenge' | 'codeChallengeMethod'>;
export type AuthorizationCodeSaved = AuthorizationCodeToSave & { client: Pick<Client, 'id' | 'name'>, user: User, owner: { name: string | null, url: string | null }, rememberApproval: boolean, scopesToApprove: string[] };
export type PublicAuthorizationCodeDetails = Pick<AuthorizationCodeSaved, 'scope' | 'client'>;
export type Token = Pick<TokenWithClientUser, 'accessToken' | 'accessTokenExpiresAt' | 'refreshToken' | 'refreshTokenExpiresAt' | 'scope'>;
export type ClientWithCredentials = Client & { name: string, secrets: string[], owner_name: string | null, owner_url: string | null };
export type User = { id: string; $state: string | null };

export type InternalToken = {
	id: number;
	type: string;
	name: string;
	value: string;
	scopes: string[];
	origins: string[];
	expire: Date | null;
	date_last_used: Date | null;
	app_id: string | null;
	parent: number | null;
	user_created: string;
};

export type InternalTokenRow = Omit<InternalToken, 'scopes' | 'origins'> & {
	scopes: string;
	origins: string;
};

export type ClientRow = {
	id: string;
	name: string;
	owner_name: string | null;
	owner_url: string | null;
	secrets: string;
	redirect_urls: string;
	grants: string;
	access_token_lifetime: number | null;
	refresh_token_lifetime: number | null;
};

export type Approval = {
	scopes: string;
}

export type InternalUser = {
	id: string;
	github_username: string;
}

export type OAuthRouteOptions = {
	dashHost: string;
	docsHost: string;
	serverHost: string;
	directusHost: string;
};

export type ApproveRequest = {
	approved: number;
};

export type IntrospectionRequest = {
	token: string;
};

export type RevocationRequest = {
	token: string;
};

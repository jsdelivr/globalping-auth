import { createHash } from 'node:crypto';
import { generateRandomCodeVerifier, calculatePKCECodeChallenge } from 'oauth4webapi';
import { base32 } from '@scure/base';
import { expect } from 'chai';
import * as jose from 'jose';
import Bluebird from 'bluebird';
import config from 'config';
import request, { Agent } from 'supertest';
import type { Server } from 'node:http';

import { client as sql } from '../../../src/lib/sql/client.js';
import { getTestServer } from '../../utils/server.js';
import { apps, users } from '../../../seeds/test/index.js';

const sessionSecret = config.get<string>('server.session.cookieSecret');

const tokenEndpoint = '/oauth/token';
const revocationEndpoint = '/oauth/token/revoke';
const introspectionEndpoint = '/oauth/token/introspect';
const authorizationEndpoint = '/oauth/authorize';

const user1 = users[0]!;
const client1 = apps[0]!;
const client2 = apps[1]!;

describe('OAuth', () => {
	let app: Server;
	let requestAgent: Agent;
	let codeVerifier: string;
	let codeChallenge: string;
	let user1Cookie: string;

	const getApprovalUrl = (location: string): string => {
		return new URL(location).pathname.replace('authorize', 'oauth/approve');
	};

	const defaultAuthorizationRequest = (client: typeof apps[number], headers = {}, query = {}) => {
		return requestAgent
			.get(authorizationEndpoint)
			.set('Cookie', `dash_session_token=${user1Cookie}`)
			.set(headers)
			.query({
				client_id: client.id,
				redirect_uri: client.redirect_url,
				response_type: 'code',
				scope: 'measurements',
				state: 'someRandomState',
				code_challenge: codeChallenge,
				code_challenge_method: 'S256',
				...query,
			});
	};

	const getAuthorizationCode = async (client: typeof apps[number]): Promise<string> => {
		const res1 = await defaultAuthorizationRequest(client);

		expect(res1.status).to.equal(302);
		expect(res1.headers['location']).to.include(`https://dash.globalping.io/authorize/`);

		const res2 = await requestAgent
			.post(getApprovalUrl(res1.headers['location']!))
			.set('Cookie', `dash_session_token=${user1Cookie}`)
			.send({ approved: 1 });

		expect(res2.status).to.equal(302);
		expect(res2.headers['location']).to.include(`code=`);
		expect(res2.headers['location']).to.include(`state=someRandomState`);

		return new URL(res2.headers['location']!).searchParams.get('code')!;
	};

	const defaultTokenRequest = async (client: typeof apps[number], headers = {}, body = {}) => {
		const authorizationCode = await getAuthorizationCode(client);

		return requestAgent
			.post(tokenEndpoint)
			.set('Content-Type', 'application/x-www-form-urlencoded')
			.set(headers)
			.send({
				client_id: client.id,
				client_secret: client.secret,
				code: authorizationCode,
				redirect_uri: client.redirect_url,
				grant_type: 'authorization_code',
				code_verifier: codeVerifier,
				...body,
			});
	};

	before(async () => {
		app = await getTestServer();
		requestAgent = request(app);
		codeVerifier = generateRandomCodeVerifier();
		codeChallenge = await calculatePKCECodeChallenge(codeVerifier);

		user1Cookie = await new jose.SignJWT({ id: '4c504c2b-b53c-48d6-a526-2e3194cd6740', app_access: 1 })
			.setProtectedHeader({ alg: 'HS256' })
			.setIssuedAt()
			.setExpirationTime('1h')
			.sign(Buffer.from(sessionSecret));
	});

	describe('Authorization Endpoint', () => {
		it('should successfully authorize with correct parameters and user approval', async () => {
			expect(apps).to.have.length.greaterThan(1);

			await Bluebird.map(apps, app => getAuthorizationCode(app));
		});

		it('should fail authorization if the user cancels the approval', async () => {
			const res1 = await defaultAuthorizationRequest(client1);

			expect(res1.status).to.equal(302);
			expect(res1.headers['location']).to.include(`https://dash.globalping.io/authorize/`);

			const res2 = await requestAgent
				.post(getApprovalUrl(res1.headers['location']!))
				.set('Cookie', `dash_session_token=${user1Cookie}`)
				.send({ approved: 0 });

			expect(res2.status).to.equal(302);
			expect(res2.headers['location']).to.include(`error=access_denied`);
			expect(res2.headers['location']).to.include(`state=someRandomState`);

			const res3 = await requestAgent
				.post(getApprovalUrl(res1.headers['location']!))
				.set('Cookie', `dash_session_token=${user1Cookie}`)
				.send({ approved: 1 });

			expect(res3.status).to.equal(400);
		});

		it('should fail authorization with missing response_type', async () => {
			const res = await defaultAuthorizationRequest(client1, {}, {
				response_type: '',
			});

			expect(res.status).to.equal(302);
			expect(res.headers).to.have.property('location').that.includes('error=invalid_request');
		});

		it('should fail authorization with invalid client_id', async () => {
			const res = await defaultAuthorizationRequest(client1, {}, {
				client_id: 'invalid-client-id',
			});

			expect(res.status).to.equal(400);
			expect(res.body).to.have.property('error', 'invalid_client');
			expect(res.body).to.have.property('error_description').that.includes('client is invalid');
		});

		it('should fail authorization with mismatched redirect_uri', async () => {
			const res = await defaultAuthorizationRequest(client1, {}, {
				redirect_uri: 'https://wrongurl.com/callback',
			});

			expect(res.status).to.equal(400);
			expect(res.body).to.have.property('error', 'invalid_client');
			expect(res.body).to.have.property('error_description').that.includes('redirect_uri');
		});

		it('should fail authorization with missing scope', async () => {
			const res = await defaultAuthorizationRequest(client1, {}, {
				scope: '',
			});

			expect(res.status).to.equal(302);
			expect(res.headers).to.have.property('location').that.includes('error=invalid_scope');
			expect(res.headers).to.have.property('location').that.includes(`state=someRandomState`);
		});

		it('should fail authorization with unsupported response_type', async () => {
			const res = await defaultAuthorizationRequest(client1, {}, {
				response_type: 'unsupported',
			});

			expect(res.status).to.equal(302);
			expect(res.headers).to.have.property('location').that.includes('error=unsupported_response_type');
			expect(res.headers).to.have.property('location').that.includes(`state=someRandomState`);
		});

		it('should fail authorization when PKCE is not provided for public clients', async () => {
			const res = await defaultAuthorizationRequest(client1, {}, {
				code_challenge: '',
			});

			expect(res.status).to.equal(302);
			expect(res.headers).to.have.property('location').that.includes('error=invalid_request');
			expect(res.headers).to.have.property('location').that.includes('error_description=Missing');
			expect(res.headers).to.have.property('location').that.includes(`state=someRandomState`);
		});

		it('should fail authorization when PKCE is not provided for private clients', async () => {
			const res = await defaultAuthorizationRequest(client2, {}, {
				code_challenge: '',
			});

			expect(res.status).to.equal(302);
			expect(res.headers).to.have.property('location').that.includes('error=invalid_request');
			expect(res.headers).to.have.property('location').that.includes('error_description=Missing');
			expect(res.headers).to.have.property('location').that.includes(`state=someRandomState`);
		});

		it('should redirect to the login page if the user does not have a valid session', async () => {
			const res = await defaultAuthorizationRequest(client1, {
				cookie: '',
			});

			expect(res.status).to.equal(302);
			expect(res.headers).to.have.property('location').that.includes(`https://dash-directus.globalping.io/auth/login`);
		});
	});

	describe('Token Endpoint', () => {
		it('should successfully exchange authorization code for access token', async () => {
			const res = await defaultTokenRequest(client1);

			expect(res.status).to.equal(200);
			expect(res.body).to.have.property('access_token');
			expect(res.body).to.have.property('refresh_token');
			expect(res.body).to.have.property('expires_in');
			expect(res.body).to.have.property('token_type', 'Bearer');
			expect(res.body).to.have.property('scope', 'measurements');
		});

		it('should fail with invalid client_secret if the client has one', async () => {
			const res1 = await defaultTokenRequest(client2, {}, {
				client_secret: 'xxx',
			});

			expect(res1.status).to.equal(400);
			expect(res1.body).to.have.property('error', 'invalid_client');
			expect(res1.body).to.have.property('error_description').that.includes('client credentials are invalid');

			const res2 = await defaultTokenRequest(client2, {}, {
				client_secret: 'secret2',
			});

			expect(res2.status).to.equal(200);
			expect(res2.body).to.have.property('access_token');
		});

		it('should fail with unsupported grant_type', async () => {
			const res = await defaultTokenRequest(client2, {}, {
				grant_type: 'client_credentials',
			});

			expect(res.status).to.equal(400);
			expect(res.body).to.have.property('error', 'unauthorized_client');
			expect(res.body).to.have.property('error_description').that.includes('grant_type');
		});


		it('should fail with invalid authorization code', async () => {
			const res = await defaultTokenRequest(client1, {}, {
				code: 'invalid_code',
			});

			expect(res.status).to.equal(400);
			expect(res.body).to.have.property('error', 'invalid_grant');
			expect(res.body).to.have.property('error_description').that.includes('authorization code is invalid');
		});

		it('should fail with invalid client_id', async () => {
			const res = await defaultTokenRequest(client1, {}, {
				client_id: 'invalid_client_id',
			});

			expect(res.status).to.equal(400);
			expect(res.body).to.have.property('error', 'invalid_client');
			expect(res.body).to.have.property('error_description').that.includes('client is invalid');
		});

		it('should fail with invalid redirect_uri', async () => {
			const res = await defaultTokenRequest(client1, {}, {
				redirect_uri: 'https://wrongurl.com/callback',
			});

			expect(res.status).to.equal(400);
			expect(res.body).to.have.property('error', 'invalid_request');
			expect(res.body).to.have.property('error_description').that.includes('redirect_uri');
		});

		it('should fail with missing code_verifier for public clients', async () => {
			const res = await defaultTokenRequest(client1, {}, {
				code_verifier: '',
			});

			expect(res.status).to.equal(400);
			expect(res.body).to.have.property('error', 'invalid_client');
			expect(res.body).to.have.property('error_description').that.includes('cannot retrieve client credentials');
		});

		it('should fail with missing code_verifier for private clients', async () => {
			const res = await defaultTokenRequest(client2, {}, {
				code_verifier: '',
			});

			expect(res.status).to.equal(400);
			expect(res.body).to.have.property('error', 'invalid_grant');
			expect(res.body).to.have.property('error_description').that.includes('code_verifier');
		});
	});

	describe('Refresh Token Grant', () => {
		it('should successfully exchange refresh token for new access token', async () => {
			// Get the initial token response to retrieve the refresh token
			const initialTokenResponse = await defaultTokenRequest(client1);
			expect(initialTokenResponse.status).to.equal(200);
			const refreshToken = initialTokenResponse.body.refresh_token;

			// Use the refresh token to get a new access token
			const res = await requestAgent
				.post(tokenEndpoint)
				.set('Content-Type', 'application/x-www-form-urlencoded')
				.send({
					client_id: client1.id,
					client_secret: client1.secret,
					refresh_token: refreshToken,
					grant_type: 'refresh_token',
				});

			expect(res.status).to.equal(200);
			expect(res.body).to.have.property('access_token');
			expect(res.body).to.have.property('refresh_token');
			expect(res.body).to.have.property('expires_in');
			expect(res.body).to.have.property('token_type', 'Bearer');
			expect(res.body).to.have.property('scope', 'measurements');
		});

		it('should fail with invalid refresh token', async () => {
			const res = await requestAgent
				.post(tokenEndpoint)
				.set('Content-Type', 'application/x-www-form-urlencoded')
				.send({
					client_id: client1.id,
					client_secret: client1.secret,
					refresh_token: 'invalid_refresh_token',
					grant_type: 'refresh_token',
				});

			expect(res.status).to.equal(400);
			expect(res.body).to.have.property('error', 'invalid_grant');
			expect(res.body).to.have.property('error_description').that.includes('refresh token is invalid');
		});

		it('should fail with expired refresh token', async () => {
			// Obtain a valid refresh token first
			const initialTokenResponse = await defaultTokenRequest(client1);
			expect(initialTokenResponse.status).to.equal(200);
			const refreshToken = initialTokenResponse.body.refresh_token;

			// Simulate token expiration.
			await sql('gp_tokens')
				.where({
					value: createHash('sha256').update(base32.decode(refreshToken.toUpperCase())).digest('base64'),
				})
				.update({
					expire: new Date(Date.now() - 600000),
				});

			const res = await requestAgent
				.post(tokenEndpoint)
				.set('Content-Type', 'application/x-www-form-urlencoded')
				.send({
					client_id: client1.id,
					client_secret: client1.secret,
					refresh_token: refreshToken,
					grant_type: 'refresh_token',
				});

			expect(res.status).to.equal(400);
			expect(res.body).to.have.property('error', 'invalid_grant');
			expect(res.body).to.have.property('error_description').that.includes('refresh token has expired');
		});

		it('should fail with missing refresh token', async () => {
			const res = await requestAgent
				.post(tokenEndpoint)
				.set('Content-Type', 'application/x-www-form-urlencoded')
				.send({
					client_id: client1.id,
					client_secret: client1.secret,
					grant_type: 'refresh_token',
				});

			expect(res.status).to.equal(400);
			expect(res.body).to.have.property('error', 'invalid_request');
			expect(res.body).to.have.property('error_description').that.includes('refresh_token');
		});
	});

	describe('Token Revocation', () => {
		const getTokenFromDB = (token: string) => {
			return sql('gp_tokens').where({ value: createHash('sha256').update(base32.decode(token.toUpperCase())).digest('base64') }).first();
		};

		const revokeToken = async (token: string | undefined, client: typeof apps[number]) => {
			return requestAgent
				.post(revocationEndpoint)
				.set('Content-Type', 'application/x-www-form-urlencoded')
				.send({
					token,
					client_id: client.id,
					client_secret: client.secret,
				});
		};

		it('should successfully revoke an access token', async () => {
			// Obtain a valid access token
			const tokenResponse = await defaultTokenRequest(client1);
			expect(tokenResponse.status).to.equal(200);

			const accessToken = tokenResponse.body.access_token;
			expect(await getTokenFromDB(accessToken)).to.be.an('object');

			// Revoke the access token
			const revokeResponse = await revokeToken(accessToken, client1);
			expect(revokeResponse.status).to.equal(200);

			expect(await getTokenFromDB(accessToken)).to.be.undefined;
		});

		it('should successfully revoke a refresh token and its associated access token', async () => {
			// Obtain a valid refresh token
			const tokenResponse = await defaultTokenRequest(client1);
			expect(tokenResponse.status).to.equal(200);

			const refreshToken = tokenResponse.body.refresh_token;
			expect(await getTokenFromDB(refreshToken)).to.be.an('object');

			// Revoke the refresh token
			const revokeResponse = await revokeToken(refreshToken, client1);
			expect(revokeResponse.status).to.equal(200);

			expect(await getTokenFromDB(refreshToken)).to.be.undefined;
			expect(await getTokenFromDB(tokenResponse.body.access_token)).to.be.undefined;
		});

		it('should successfully revoke a non-existing token', async () => {
			const revokeResponse = await revokeToken('invalid_token', client1);
			expect(revokeResponse.status).to.equal(200);
		});

		it('should successfully revoke an already revoked token', async () => {
			// Obtain and revoke a token
			const tokenResponse = await defaultTokenRequest(client1);
			expect(tokenResponse.status).to.equal(200);
			const accessToken = tokenResponse.body.access_token;

			// Revoke the token
			const revokeResponse1 = await revokeToken(accessToken, client1);
			expect(revokeResponse1.status).to.equal(200);

			// Revoke the token again
			const revokeResponse2 = await revokeToken(accessToken, client1);
			expect(revokeResponse2.status).to.equal(200);
		});

		it('should fail revocation with a missing token', async () => {
			const res = await revokeToken(undefined, client1);

			expect(res.status).to.equal(400);
			expect(res.body).to.have.property('error', 'invalid_request');
			expect(res.body).to.have.property('error_description').that.includes('`token` is required');
		});
	});

	describe('Token Introspection', () => {
		const introspectToken = async (token: string | undefined, client: typeof apps[number]) => {
			return requestAgent
				.post(introspectionEndpoint)
				.set('Content-Type', 'application/x-www-form-urlencoded')
				.send({
					token,
					client_id: client.id,
					client_secret: client.secret,
				});
		};

		it('should successfully introspect a valid access token', async () => {
			// Obtain a valid access token
			const tokenResponse = await defaultTokenRequest(client1);
			expect(tokenResponse.status).to.equal(200);
			const accessToken = tokenResponse.body.access_token;

			// Introspect the access token
			const introspectResponse = await introspectToken(accessToken, client1);
			expect(introspectResponse.status).to.equal(200);

			// Validate the introspection response
			expect(introspectResponse.body).to.have.property('active', true);
			expect(introspectResponse.body).to.have.property('scope', 'measurements');
			expect(introspectResponse.body).to.have.property('client_id', client1.id);
			expect(introspectResponse.body).to.have.property('username', user1.github_username);
		});

		it('should successfully introspect a valid refresh token', async () => {
			// Obtain a valid refresh token
			const tokenResponse = await defaultTokenRequest(client1);
			expect(tokenResponse.status).to.equal(200);
			const refreshToken = tokenResponse.body.refresh_token;

			// Introspect the refresh token
			const introspectResponse = await introspectToken(refreshToken, client1);
			expect(introspectResponse.status).to.equal(200);

			// Validate the introspection response
			expect(introspectResponse.body).to.have.property('active', true);
			expect(introspectResponse.body).to.have.property('scope', 'measurements');
			expect(introspectResponse.body).to.have.property('client_id', client1.id);
			expect(introspectResponse.body).to.have.property('username').that.is.a('string');
		});

		it('should return inactive for an invalid token', async () => {
			const introspectResponse = await introspectToken('invalid_token', client1);

			expect(introspectResponse.status).to.equal(200);
			expect(introspectResponse.body).to.have.property('active', false);
		});

		it('should fail introspection with missing token', async () => {
			const introspectResponse = await introspectToken(undefined, client1);

			expect(introspectResponse.status).to.equal(400);
			expect(introspectResponse.body).to.have.property('error', 'invalid_request');
			expect(introspectResponse.body).to.have.property('error_description').that.includes('`token` is required');
		});
	});
});

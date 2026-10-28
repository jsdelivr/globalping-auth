import { createHash } from 'node:crypto';
import { Knex } from 'knex';

export const orgs = [
	{ id: 'org1', name: 'org-one', github_id: '1000', adoption_token: 'orgOneAdoptionToken' },
];

export const users = [
	{ id: 'user1', github_username: 'user1_github' },
	{ id: 'user2' },
	{ id: 'user3', selected_orgs: JSON.stringify([ orgs[0]!.id ]) }, // The only user who picked an org in the dashboard, so the approval screen is never skipped for them.
];

export const accounts = [
	{ id: 'user1_account', user: users[0]!.id, org: null },
	{ id: 'user2_account', user: users[1]!.id, org: null },
	{ id: 'org1_account', user: null, org: orgs[0]!.id },
	{ id: 'user3_account', user: users[2]!.id, org: null },
];

// user1 and user3 may approve apps for the org, user2 only sees it.
export const orgMembers = [
	{ id: 'org1_user1', org: orgs[0]!.id, user: users[0]!.id, role: 'member' },
	{ id: 'org1_user2', org: orgs[0]!.id, user: users[1]!.id, role: 'viewer' },
	{ id: 'org1_user3', org: orgs[0]!.id, user: users[2]!.id, role: 'admin' },
];

export const clients = [
	{
		id: '74eb66bd-1e4c-4c84-b275-e5b477da2087',
		user_created: users[0]!.id,
		name: 'App One',
		secrets: '[]',
		redirect_urls: JSON.stringify([
			'https://example.com/one/callback',
			'https://example.com/one/alternative-callback',
		]),
		grants: JSON.stringify([ 'authorization_code', 'refresh_token', 'globalping_client_credentials' ]),
	},
	{
		id: 'b2a50a7e-6dc5-423d-864e-173ea690992e',
		user_created: users[1]!.id,
		name: 'App Two',
		owner_name: 'Some Organization',
		owner_url: 'https://example.com/org',
		secrets: '["v5TSHQUuwfP+ltCV00sFdfiBcI8JC8ZCNrNB33H8IVI="]',
		redirect_urls: JSON.stringify([ 'https://example.com/two/callback' ]),
		grants: JSON.stringify([ 'authorization_code', 'refresh_token' ]),
	},
	{
		id: '3de73daa-3943-421c-9847-ce6ccc8e69c2',
		user_created: users[1]!.id,
		name: 'Slack App',
		secrets: '["OSMOYY6tV16Kc0l+BB5ml4eKXFf4JaqARFMCdudKU98="]',
		redirect_urls: JSON.stringify([ 'https://example.com/three/callback' ]),
		grants: JSON.stringify([ 'globalping_client_credentials', 'refresh_token' ]),
	},
];

export const secrets = new Map([
	[ clients[1], 'tzc2di5tmthrbxjh7vnq3v4ymicqod7eucccblyfs4ncpr7o' ],
	[ clients[2], 'bgygsrjvvwjdj73dmq7bdhrn72s4opexedf4ksjvmi6gir7a' ],
]);

export async function seed (db: Knex) {
	await db('directus_users').insert(users);
	await db('gp_orgs').insert(orgs);
	await db('gp_accounts').insert(accounts);
	await db('gp_org_members').insert(orgMembers);
	await db('gp_apps').insert(clients);

	// Insert tokens
	const tokens = [
		{
			id: 1,
			date_created: db.fn.now(),
			date_last_used: null,
			date_updated: db.fn.now(),
			expire: db.raw('NOW() + INTERVAL 1 DAY'),
			name: 'Token One',
			origins: JSON.stringify([ 'https://origin1.com' ]),
			user_created: users[0]!.id,
			user_updated: users[0]!.id,
			account_id: accounts[0]!.id,
			value: createHash('sha256').update('token1value').digest('base64'),
			app_id: clients[0]!.id,
			scopes: JSON.stringify([ 'measurements' ]),
			type: 'access_token',
			parent: null,
		},
		{
			id: 2,
			date_created: db.fn.now(),
			date_last_used: null,
			date_updated: db.fn.now(),
			expire: db.raw('NOW() + INTERVAL 1 DAY'),
			name: 'Token Three',
			origins: JSON.stringify([ 'https://origin3.com' ]),
			user_created: users[0]!.id,
			user_updated: users[0]!.id,
			account_id: accounts[0]!.id,
			value: createHash('sha256').update('token2value').digest('base64'),
			app_id: clients[1]!.id,
			scopes: JSON.stringify([ 'measurements' ]),
			type: 'refresh_token',
			parent: null,
		},
		{
			id: 3,
			date_created: db.fn.now(),
			date_last_used: null,
			date_updated: db.fn.now(),
			expire: db.raw('NOW() + INTERVAL 1 DAY'),
			name: 'Token Two',
			origins: JSON.stringify([ 'https://origin2.com' ]),
			user_created: users[1]!.id,
			user_updated: users[1]!.id,
			account_id: accounts[1]!.id,
			value: createHash('sha256').update('token3value').digest('base64'),
			app_id: clients[0]!.id,
			scopes: JSON.stringify([ 'measurements' ]),
			type: 'access_token',
			parent: 2,
		},
		{
			id: 4,
			date_created: db.fn.now(),
			date_last_used: null,
			date_updated: db.fn.now(),
			expire: db.raw('NOW() + INTERVAL 1 DAY'),
			name: 'Token Four',
			origins: JSON.stringify([ 'https://origin4.com' ]),
			user_created: users[1]!.id,
			user_updated: users[1]!.id,
			account_id: accounts[1]!.id,
			value: createHash('sha256').update('token4value').digest('base64'),
			app_id: clients[1]!.id,
			scopes: JSON.stringify([ 'measurements' ]),
			type: 'refresh_token',
			parent: null,
		},
	];

	await db('gp_tokens').insert(tokens);
}

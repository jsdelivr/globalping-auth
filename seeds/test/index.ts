import { createHash } from 'node:crypto';
import { Knex } from 'knex';

export const users = [
	{ id: '4c504c2b-b53c-48d6-a526-2e3194cd6740', github_username: 'user1_github' },
	{ id: 'dfe6d9d6-eaa0-4f7d-aa8d-439a9efeef68' },
];

export const apps = [
	{
		id: '74eb66bd-1e4c-4c84-b275-e5b477da2087',
		user_created: users[0]!.id,
		name: 'App One',
		secret: null,
		redirect_urls: JSON.stringify([ 'https://example.com/one/callback' ]),
		grants: JSON.stringify([ 'authorization_code', 'refresh_token' ]),
	},
	{
		id: 'b2a50a7e-6dc5-423d-864e-173ea690992e',
		user_created: users[1]!.id,
		name: 'App Two',
		owner_name: 'Some Organization',
		owner_url: 'https://example.com/org',
		secret: 'secret2',
		redirect_urls: JSON.stringify([ 'https://example.com/two/callback' ]),
		grants: JSON.stringify([ 'authorization_code', 'refresh_token' ]),
	},
];

export async function seed (db: Knex) {
	// Insert users
	await db('directus_users').insert(users);

	// Insert apps
	await db('gp_apps').insert(apps);

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
			value: createHash('sha256').update('token1value').digest('base64'),
			app_id: apps[0]!.id,
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
			value: createHash('sha256').update('token2value').digest('base64'),
			app_id: apps[1]!.id,
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
			value: createHash('sha256').update('token3value').digest('base64'),
			app_id: apps[0]!.id,
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
			value: createHash('sha256').update('token4value').digest('base64'),
			app_id: apps[1]!.id,
			scopes: JSON.stringify([ 'measurements' ]),
			type: 'refresh_token',
			parent: null,
		},
	];

	await db('gp_tokens').insert(tokens);
}

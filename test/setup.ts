import config from 'config';
import Bluebird from 'bluebird';
import nock from 'nock';
import type { Knex } from 'knex';

import { initRedisClient } from '../src/lib/redis/client.js';
import { client as sql } from '../src/lib/sql/client.js';

const dbConfig = config.get<{ connection: { database: string, host: string } }>('db');

if (!dbConfig.connection.database.endsWith('-test') && dbConfig.connection.host !== 'localhost') {
	throw new Error(`Database name for test env needs to end with "-test" or the host must be "localhost". Got "${dbConfig.connection.database}"@"${dbConfig.connection.host}".`);
}

before(async () => {
	const redisClient = await initRedisClient();
	await redisClient.flushDb();

	await dropAllTables(sql);
	await sql.migrate.latest();
	await sql.seed.run();

	nock.disableNetConnect();
	nock.enableNetConnect('127.0.0.1');
});

const dropAllTables = async (sql: Knex) => {
	const allTables = [
		'gp_apps_approvals',
		'gp_tokens',
		'gp_apps',
		'directus_users',
		'knex_migrations',
	];

	await Bluebird.mapSeries(allTables, table => sql.schema.raw(`drop table if exists \`${table}\``));
};

import config from 'config';
import { createClient, RedisClientOptions, RedisClientType, RedisDefaultModules, RedisFunctions, RedisScripts } from 'redis';
import { scopedLogger } from '../logger.js';

const logger = scopedLogger('redis-client');

export type RedisClient = RedisClientType<RedisDefaultModules, RedisFunctions, RedisScripts>;

export const createRedisClientInternal = (options?: RedisClientOptions): RedisClient => {
	const client = createClient({
		...config.util.toObject(config.get('redis')) as RedisClientOptions,
		...options,
	});

	client
		.on('error', (error: Error) => logger.error('connection error', error))
		.on('ready', () => logger.info('connection ready'))
		.on('reconnecting', () => logger.info('reconnecting'))
		.connect().catch((error: Error) => logger.error('connection error', error));

	return client;
};

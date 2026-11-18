import config from 'config';
import {
	createClient,
	RedisClientOptions,
	RedisClientType,
	RedisDefaultModules,
	RedisFunctions,
	RedisScripts,
} from 'redis';
import { scopedLogger } from '../logger.js';

const logger = scopedLogger('redis-client');

export type RedisClient = RedisClientType<RedisDefaultModules, RedisFunctions, RedisScripts, 3>;

export const createRedisClientInternal = (options?: RedisClientOptions): RedisClient => {
	const clientOptions = {
		...config.util.toObject(config.get('redis')) as RedisClientOptions,
		...options,
	};
	const socketOptions = { keepAliveInitialDelay: 5000, ...clientOptions.socket };
	const client = createClient({
		// Preserve the previous connection defaults.
		maintNotifications: 'disabled',
		...clientOptions,
		RESP: 3,
		commandOptions: { timeout: 0, ...clientOptions.commandOptions },
		socket: socketOptions,
	});

	client
		.on('error', (error: Error) => logger.error('Redis connection error:', error))
		.on('ready', () => logger.info('Redis connection ready.'))
		.on('reconnecting', () => logger.info('Redis reconnecting.'))
		.connect().catch((error: Error) => logger.error('Redis connection error:', error));

	return client;
};

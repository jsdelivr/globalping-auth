import type { RedisClientOptions } from 'redis';
import { createRedisClientInternal, type RedisClient } from './shared.js';

let redis: RedisClient;

export const initRedisClient = async () => {
	redis = createRedisClient();
	return redis;
};

const createRedisClient = (options?: RedisClientOptions) => {
	return createRedisClientInternal({
		...options,
		database: 1,
		name: 'persistent',
	});
};

export const getRedisClient = () => {
	if (!redis) {
		redis = createRedisClient();
	}

	return redis;
};

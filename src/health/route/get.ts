import _ from 'lodash';
import pTimeout from 'p-timeout';
import { Router, RouterContext } from '@koa/router';

import { getRedisClient } from '../../lib/redis/client.js';

const PING_OK = {};
const redis = getRedisClient();

const handle = async (ctx: RouterContext): Promise<void> => {
	const result = await throttledPing();

	if (result === PING_OK) {
		ctx.body = 'Alive';
		return;
	}

	ctx.status = 503;
	ctx.body = (result as Error).message || 'Unknown error';
};

export const registerHealthRoute = (router: Router): void => {
	router.get('/health', '/health', handle);
};


const throttledPing = _.throttle(() => {
	return pTimeout(redis.ping(), { milliseconds: 2000 }).then(() => PING_OK).catch(e => e as Error);
}, 2000, { trailing: false });

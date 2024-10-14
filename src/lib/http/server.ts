import { createServer } from 'node:http';
import * as zlib from 'node:zlib';
import * as url from 'node:url';
import json from 'koa-json';
import config from 'config';
import Router from '@koa/router';
import compress from 'koa-compress';
import responseTime from 'koa-response-time';
import koaFavicon from 'koa-favicon';
import koaStatic from 'koa-static';
import Koa from 'koa';

import { registerOAuthRoutes } from '../../oauth/route/index.js';
import { errorHandler } from './error-handler.js';
import { defaultJson } from './middleware/default-json.js';
import { errorHandlerMw } from './middleware/error-handler.js';

const app = new Koa();
const publicPath = url.fileURLToPath(new URL('.', import.meta.url)) + '/../../../public';
const docsHost = config.get<string>('server.docsHost');

const rootRouter = new Router({ strict: true, sensitive: true });
rootRouter.prefix('/');

// GET /
rootRouter.get('/', '/', (ctx) => {
	ctx.status = 404;

	ctx.body = {
		links: {
			documentation: `${docsHost}/docs/api.globalping.io`,
		},
	};
});

// /oauth
registerOAuthRoutes(rootRouter);

app
	.use(responseTime())
	.use(koaFavicon(`${publicPath}/favicon.ico`))
	.use(compress({ br: { params: { [zlib.constants.BROTLI_PARAM_QUALITY]: 4 } }, gzip: { level: 3 }, deflate: false }))
	.use(json({ pretty: true, spaces: 2 }))
	.use(defaultJson())
	// Error handler must always be the first middleware in a chain unless you know what you are doing ;)
	.use(errorHandlerMw)
	.use(async (ctx, next) => {
		await next();

		console.debug('request URL', ctx.request.url);
		console.debug('request body:', ctx.request.body);
		// eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
		console.debug('response body:', ctx.response.body.constructor.name === 'Object' ? ctx.response.body : {}.toString.call(ctx.response.body));
	})
	.use(rootRouter.routes())
	.use(rootRouter.allowedMethods())
	.use(koaStatic(publicPath, {
		format: false,
		setHeaders (res) {
			res.setHeader('Access-Control-Allow-Origin', '*');
			res.setHeader('Access-Control-Allow-Headers', '*');
			res.setHeader('Access-Control-Expose-Headers', '*');
			res.setHeader('Access-Control-Max-Age', '600');
			res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
			res.setHeader('Timing-Allow-Origin', '*');
		},
	}));

app.on('error', errorHandler);

// eslint-disable-next-line @typescript-eslint/no-misused-promises
const server = createServer(app.callback());

export const getHttpServer = () => server;

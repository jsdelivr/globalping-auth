import type Router from '@koa/router';

import { corsHandler } from '../../lib/http/middleware/cors.js';
import { authenticate } from '../../lib/http/middleware/authenticate.js';
import { bodyParser } from '../../lib/http/middleware/body-parser.js';
import { validate } from '../../lib/http/middleware/validate.js';

import { oAuthServerOptions as options } from '../server.js';
import { approveSchema, introspectSchema, revokeSchema } from '../schema.js';
import { metadataGet } from './metadata.js';
import { approveGet, approvePost } from './approve.js';
import { authorizeGet, authorizePost } from './authorize.js';
import { revokePost } from './revoke.js';
import { tokenPost } from './token.js';
import { introspectPost } from './introspect.js';

export const registerOAuthRoutes = (router: Router): void => {
	router
		.get('/.well-known/oauth-authorization-server', corsHandler(), metadataGet(options));

	router
		.get('/oauth/authorize', authenticate(), authorizeGet(options))
		.post('/oauth/authorize', authenticate(), bodyParser(), authorizePost(options));

	router
		.get('/oauth/approve/:publicCodeId', corsHandler(), approveGet)
		.post('/oauth/approve/:publicCodeId', authenticate(), bodyParser(), validate(approveSchema), approvePost);

	router
		.post('/oauth/token', bodyParser(), tokenPost());

	router
		.post('/oauth/token/introspect', bodyParser(), validate(introspectSchema), introspectPost());

	router
		.post('/oauth/token/revoke', bodyParser(), validate(revokeSchema), revokePost());
};

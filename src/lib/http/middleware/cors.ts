import { ExtendedMiddleware } from '../../../types.js';

export const corsHandler = (): ExtendedMiddleware => async (ctx, next) => {
	ctx.set('Access-Control-Allow-Origin', '*');
	ctx.set('Access-Control-Allow-Headers', '*');
	ctx.set('Access-Control-Expose-Headers', '*');
	ctx.set('Access-Control-Max-Age', '600');
	ctx.set('Cross-Origin-Resource-Policy', 'cross-origin');
	ctx.set('Timing-Allow-Origin', '*');

	await next();
};

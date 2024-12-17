import createHttpError from 'http-errors';
import { scopedLogger } from '../../logger.js';
import { ExtendedMiddleware } from '../../../types.js';

const logger = scopedLogger('error-handler-mw');

export const errorHandlerMw: ExtendedMiddleware = async (ctx, next) => {
	try {
		await next();
	} catch (error: unknown) {
		if (createHttpError.isHttpError(error)) {
			ctx.status = error.status;

			ctx.body = {
				error: error['type'] as string ?? 'server_error',
				error_description: error.expose ? error.message : `${createHttpError(error.status).message}`,
			};

			return;
		}

		logger.error('Internal server error:', error);

		ctx.status = 500;

		ctx.body = {
			error: 'server_error',
			error_description: 'Internal Server Error',
		};
	}
};

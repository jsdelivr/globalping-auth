import type { Schema } from 'joi';
import type { ExtendedMiddleware } from '../../../types.js';
import _ from 'lodash';

export const validate = (schema: Schema): ExtendedMiddleware => async (ctx, next) => {
	const valid = schema.validate(ctx.request.body, {
		convert: true,
		context: ctx.state,
		errors: {
			wrap: {
				label: '`',
			},
		},
	});

	if (valid.error) {
		ctx.status = 400;

		ctx.body = {
			error: 'invalid_request',
			error_description: `Invalid parameter value: ${_.sortBy(valid.error.details, 'path').map(detail => detail.message).join(', ')}.`,
		};

		return;
	}

	ctx.request.body = valid.value as never;
	await next();
};

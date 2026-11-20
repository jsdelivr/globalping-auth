import Joi from 'joi';

export const approveSchema = Joi.object({
	approved: Joi.number().integer().required(),
	accountId: Joi.string().max(36).empty([ null, '' ]).when('approved', { not: 0, then: Joi.required() }),
}).unknown(true);

export const introspectSchema = Joi.object({
	token: Joi.string().required(),
}).unknown(true);

export const revokeSchema = Joi.object({
	token: Joi.string().required(),
}).unknown(true);

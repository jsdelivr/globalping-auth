import Joi from 'joi';

export const approveSchema = Joi.object({
	approved: Joi.number().integer().required(),
	// PHASE5: require `accountId`. The deployed approval screen posts only `approved`, so until it names the account a missing one means the personal one.
	accountId: Joi.string().max(36).empty([ null, '' ]),
}).unknown(true);

export const introspectSchema = Joi.object({
	token: Joi.string().required(),
}).unknown(true);

export const revokeSchema = Joi.object({
	token: Joi.string().required(),
}).unknown(true);

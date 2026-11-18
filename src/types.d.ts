import Koa from 'koa';
import { RouterContext, RouterMiddleware } from '@koa/router';
import { AuthenticateState } from './lib/http/middleware/authenticate.js';

export type CustomState = Koa.DefaultState & AuthenticateState;
export type CustomContext = Koa.DefaultContext;

export type ExtendedContext = RouterContext<CustomState, CustomContext>;
export type ExtendedMiddleware = RouterMiddleware<CustomState, CustomContext>;

import type Koa from 'koa';
import type Router from '@koa/router';
import type { AuthenticateState } from './lib/http/middleware/authenticate.js';

export type CustomState = Koa.DefaultState & AuthenticateState;
export type CustomContext = Koa.DefaultContext & Router.RouterParamContext;

export type ExtendedContext = Router.RouterContext<CustomState, CustomContext>;
export type ExtendedMiddleware = Router.Middleware<CustomState, CustomContext>;

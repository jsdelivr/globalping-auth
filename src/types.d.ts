import Koa from 'koa';
import Router from '@koa/router';
import { AuthenticateState } from './lib/http/middleware/authenticate.js';

export type CustomState = Koa.DefaultState & AuthenticateState;
export type CustomContext = Koa.DefaultContext & Router.RouterParamContext;

export type ExtendedContext = Router.RouterContext<CustomState, CustomContext>;
export type ExtendedMiddleware = Router.Middleware<CustomState, CustomContext>;

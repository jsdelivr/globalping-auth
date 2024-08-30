import type { Server } from 'node:http';

export const createServer = async (): Promise<Server> => {
	const { getHttpServer } = await import('./http/server.js');
	return getHttpServer();
};

module.exports = {
	server: {
		host: 'http://localhost:13110',
		dashHost: 'http://localhost:13010',
		directusHost: 'http://localhost:18055',
		session: {
			cookieSecret: 'xxx',
		},
	},
	redis: {
		url: 'redis://localhost:16379',
		socket: {
			tls: false,
		},
	},
	db: {
		connection: {
			port: 13306,
		},
	},
};

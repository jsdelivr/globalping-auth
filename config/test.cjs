module.exports = {
	server: {
		session: {
			cookieSecret: 'xxx',
		},
	},
	redis: {
		url: 'redis://localhost:7001',
		socket: {
			tls: false,
		},
	},
	db: {
		connection: {
			port: 13306,
			database: 'dashboard-globalping-test',
			multipleStatements: true,
		},
	},
	auth: {
		validScopes: [ 'measurements', 'probes' ],
	},
};

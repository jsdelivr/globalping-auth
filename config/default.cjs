module.exports = {
	server: {
		host: 'https://auth.globalping.io',
		docsHost: 'https://www.jsdelivr.com',
		dashHost: 'https://dash.globalping.io',
		directusHost: 'https://dash-directus.globalping.io',
		port: 13110,
		processes: 1,
		session: {
			cookieName: 'dash_session_token',
			cookieSecret: '',
		},
	},
	redis: {
		url: 'redis://localhost:6379',
		socket: {
			tls: false,
		},
	},
	db: {
		type: 'mysql',
		connection: {
			host: 'localhost',
			user: 'directus',
			password: 'password',
			database: 'dashboard-globalping',
			port: 3306,
		},
	},
};

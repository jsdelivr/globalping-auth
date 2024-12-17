module.exports = {
	active: process.env.NODE_ENV === 'production',
	serviceName: 'globalping-auth',
	serviceVersion: process.env.RENDER_GIT_COMMIT || require('./package.json').version,
	logLevel: 'fatal',
	centralConfig: false,
	captureExceptions: false,
	captureErrorLogStackTraces: 'always',
	ignoreUrls: [ '/favicon.ico', '/health', '/amp_preconnect_polyfill_404_or_other_error_expected._Do_not_worry_about_it' ],
	transactionSampleRate: 1,
	exitSpanMinDuration: '2ms',
	spanCompressionSameKindMaxDuration: '10ms',
};

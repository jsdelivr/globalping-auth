export default function wallaby (wallaby) {
	return {
		testFramework: 'mocha',
		files: [
			'public/v1/*',
			'src/**/*.ts',
			'src/**/*.json',
			'config/*',
			'seeds/**/*',
			'migrations/**/*',
			'test/utils/**/*.ts',
			'test/mocks/**/*',
			'test/plugins/**/*',
			'test/setup.ts',
			'package.json',
			'knexfile.js',
		],
		tests: [
			'test/tests/**/*.test.ts',
		],
		setup (w) {
			const path = require('path');
			w.testFramework.files.unshift(path.resolve(process.cwd(), 'test/setup.js'));
			const mocha = w.testFramework;
			mocha.timeout(10000);
		},
		env: {
			type: 'node',
			params: {
				runner: '--experimental-specifier-resolution=node',
				env: 'NODE_ENV=test;NEW_RELIC_ENABLED=false;NEW_RELIC_LOG_ENABLED=false',
			},
		},
		compilers: {
			'**/*.ts?(x)': wallaby.compilers.typeScript({
				module: 'ESNext',
			}),
		},
		preprocessors: {
			'**/*.ts': file => file.content.replace(/\.ts/g, '.js'),
		},
		workers: { restart: true, initial: 1, regular: 1 },
		runMode: 'onsave',
	};
}

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

		env: {
			type: 'node',
			params: {
				runner: '--experimental-specifier-resolution=node',
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
		runMode: 'onsave',
	};
}

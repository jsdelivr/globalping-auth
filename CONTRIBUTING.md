# Contributing guide

Hi! We're really excited that you're interested in contributing! Before submitting your contribution, please read through the following guide.

## General guidelines

-   Bug fixes and changes discussed in the existing issues are always welcome.
-   For new ideas, please open an issue to discuss them before sending a PR.
-   Make sure your PR passes `npm test` and has [appropriate commit messages](https://github.com/jsdelivr/globalping-auth/commits/master).

## Project setup

In order to run the Globalping Auth locally you will need Node.js 20 and Redis with [RedisJSON](https://oss.redis.com/redisjson/) module and MariaDB. All of them are included in [docker-compose.yml file](https://github.com/jsdelivr/globalping/blob/master/docker-compose.yml) of the main Globalping repository.

You can run the project by following these steps:

1. Clone this repository.
2. `npm install`
3. Run `npm run start:dev`

### Environment variables
- `PORT=13110` environment variable can start the API on another port (default is 13110)

### Testing

A single command to run everything: `npm test`

To run a specific linter or a test suite, please see the scripts section of [package.json](package.json).

Most IDEs have plugins integrating the used linter (eslint), including support for automated fixes on save.

## Production config

### Environment variables

- `ELASTIC_APM_SERVER_URL={value}` used in production to send APM metrics to elastic
- `ELASTIC_APM_SECRET_TOKEN={value}` used in production to send APM metrics to elastic
- `ELASTIC_SEARCH_URL={value}` used in production to send logs to elastic
- `SERVER_SESSION_COOKIE_SECRET={value}` used to read the shared session cookie
- `REDIS_URL` used in production to set the redis URL including credentials
- `DB_CONNECTION_HOST`, `DB_CONNECTION_USER`, `DB_CONNECTION_PASSWORD`, and `DB_CONNECTION_DATABASE` database connection details

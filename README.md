# CloudFoundry GitHub OAuth Route Service

[![Build Status](https://travis-ci.com/vixus0/cf-github-route-service.svg?branch=master)](https://travis-ci.com/vixus0/cf-github-route-service)

This is a Cloud Foundry route service that authenticates people using GitHub OAuth.
You can use it when you want to restrict access to your Cloud Foundry app based on GitHub organisation.

## Development

Run tests:

```sh
go test
```

## Configuration

The following environment variables are required for the route service:

- `HOSTNAME`: The hostname which your route service will be fronting
- `CLIENT_ID`: The GitHub OAuth Application client ID
- `CLIENT_SECRET`: The GitHub OAuth Application client secret
- `GITHUB_ORG`: The GitHub organisation you want to restrict access to

The GitHub OAuth Application should be configured with a callback URL of:

    <HOSTNAME>/__oauth/callback

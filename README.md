# CloudFoundry Basic Auth Route Service

This is a Proof-of-Concept CloudFoundry app that implements a
[route-service](https://docs.cloudfoundry.org/services/route-services.html) to
add HTTP basic authentication to an application.

This uses a single pre-configured username and password. These are configured
by setting the `AUTH_USERNAME` and `AUTH_PASSWORD` environment variables, which
can be set with the `cf set-env` command.

If your CF deployment has a self-signed SSL certificate, set the
`SKIP_SSL_VALIDATION` environment variable to avoid SSL errors when proxying to
the backend.

# Nexus3 External Auth Plugin (JWT and OpenID Connect)
This is a plugin for [Sonatype Nexus OSS][Nexus] that allows authentication of externally defined users via JWTs and
(to a certain extent) OpenID connect.

Features implemented:
  - Authentication via JWTs in request headers.
  - Authentication with OpenID Connect ID tokens (i.e. using the "implicit" flow).
  - Authentication with an OpenID Connect IP using OAuth access tokens and the "on behalf of" flow. This can be combined
    with an [OAuth2 reverse proxy][OAuth2 Proxy] to achieve something approaching full OpenID authentication.
  - Mapping user roles from a JWT claim.
  - Provisioning of multiple permanent JWT API keys per user, for use with build tools, etc.
  - Automatic refreshing of OpenID Connect tokens when a user authenticates with one of the above JWT API keys,
    to check the user associated with the API key is still valid.
    
Features not implemented / known limitations:
  - The standard "authorization code" OAuth2 flow is not implemented.
    Put Nexus behind an [OAuth2 Proxy] to achieve this.
  - OpenID Connect user information is not persisted across restarts. This means an OpenID Connect user will not be able
    to authenticate using a JWT API key until they have authenticated at least once using OpenID Connect.
  - OpenID Connect tokens are only refreshed when the user logs in. This means that if an OpenID Connect user doesn't
    log in for longer than the expiry time of their refresh token, they will not be able to authenticate using a JWT
    API key until they have authenticated again using OpenID Connect.
  - There is no UI for displaying/creating/deleting JWT API keys. At present, you need to use an HTTP client such as
    curl or Postman to administer these.
    
## Installation

The plugin can be installed just as any other Karaf bundle. See the
[Nexus documentation](https://help.sonatype.com/repomanager3/bundle-development/installing-bundles) for more details.

You can also take a look at the `docker-compose.yaml` file in the repository for a basic example.

## OpenID Connect Setup

1. Configure an OpenID Connect identity provider, and obtain a client ID and secret. If you want users to be able to use
   permanent JWT API keys, you need to enable use of the "on behalf of" flow so Nexus can obtain refresh tokens -
   ensure the token endpoint will accept the clients own access tokens as assertions.
   
1. Activate the "External Realm (JWT and OpenID connect)" realm.
   
1. Create a "JWT extract header" capability
   (Note: if enabling "on behalf of" authentication, this assumes the passed access token will be a JWT).
   
1. Create an "OpenID Connect authentication" capability.

1. Create roles matching the IDs that will be passed in the configured roles claim, with the desired permissions.
   
1. Setup a reverse proxy in front of Nexus that performs the OpenID authentication. If you need to use permanent JWT API
   keys, have it pass an access token in the header configured above. Otherwise, just pass the ID token.
   
   _Take a look at the `docker-compose.yaml` file in the repository for a basic example. To get it to work,
   you will need to copy `deploy-conf/oauth2-proxy.example.conf` to `deploy-conf/oauth2-proxy.conf` and change its
   content as appropriate._
   
## JWT API Key Setup

1. Create a "JWT extract header" capability.
   
1. Create a "JWT API keys" capability.

### Administering API keys

As an authenticated user:
  - To list your own current API key IDs, send an HTTP `GET` request to `<nexus_url>/service/rest/jwtapikeys`.
  - To create a new API key for yourself, send an HTTP `PUT` request to `<nexus_url>/service/rest/jwtapikeys/<key_id>`.
    The `key_id` can be any short unique name that helps you to identify what the key is used for (e.g. `laptop_maven`).
    The response will be a newly generated JWT you can use to authenticate by passing in the header configured above.
  - To delete/revoke an API key, send an HTTP `DELETE` request to `<nexus_url>/service/rest/jwtapikeys/<key_id>`.

## Development
You can build the project with the integrated maven wrapper like so: `./mvnw clean install`.

To test changes in a local deployment, you can use Docker Compose with the config in this repository. To get it to work,
you will need to copy `deploy-conf/oauth2-proxy.example.conf` to `deploy-conf/oauth2-proxy.conf` and change its content
as appropriate.

## Credits

Credit to [nexus3-github-oauth-plugin](https://github.com/L21s/nexus3-github-oauth-plugin) that acted as a starting
point for this project. Lots of code snippets were also scraped by digging around the plugins in the main
[nexus-public](https://github.com/sonatype/nexus-public) repository. Obviously, a shout-out to [Sonatype] for producing
Nexus itself, and hosting Maven Central. Finally, credit to [OAuth2 Proxy] for providing the necessary other component
for me to duct-tape this all together.

[Nexus]: https://www.sonatype.com/products/repository-oss?topnav=true
[Sonatype]: https://www.sonatype.com/
[OAuth2 Proxy]: https://oauth2-proxy.github.io/oauth2-proxy/ 

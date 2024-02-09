# Spring Authorization Server

Customized from sample at [https://github.com/spring-projects/spring-authorization-server](https://github.com/spring-projects/spring-authorization-server).

## Requirements

To run this server you need at least a Java 17 runtime as this project uses spring boot 3.x.

## Usage

Start the server by running the class _com.example.spring.authorizationserver.SpringAuthorizationServerApplication_.

Look up the OAuth2/OIDC configuration from [http://localhost:9000/.well-known/openid-configuration](http://localhost:9000/.well-known/openid-configuration) to configure your clients and resource servers.

These are the most important configuration settings:

| Configuration Parameter | Value                                   | 
|-------------------------|-----------------------------------------|
| issuer                  | http://localhost:9000                   |
| authorization_endpoint  | http://localhost:9000/oauth2/authorize  |
| token_endpoint          | http://localhost:9000/oauth2/token      |
| jwks_uri                | http://localhost:9000/oauth2/jwks       |
| userinfo_endpoint       | http://localhost:9000/userinfo          |
| introspection_endpoint  | http://localhost:9000/oauth2/introspect |

## Registered Clients

This server comes with predefined registered OAuth2/OIDC clients:

| Client ID               | Client-Secret | PKCE | Access Token Format |
|-------------------------|---------------|------|---------------------|
| demo-client             | secret        | --   | JWT                 |
| demo-client-pkce        | secret        | X    | JWT                 |
| demo-client-opaque      | secret        | --   | Opaque              |
| demo-client-pkce-opaque | secret        | X    | Opaque              |

All clients have configured the following redirect URIs (including a special one for postman):

* http://127.0.0.1:9095/client/callback
* http://127.0.0.1:9095/client/authorized
* http://127.0.0.1:9095/client
* http://127.0.0.1:9095/login/oauth2/code/spring-authz-server
* https://oauth.pstmn.io/v1/callback

__Please note__: Instead of _localhost_ the local ip _127.0.0.1_ is configured as redirect URI. This is because spring security does not allow redirects of clients to localhost addresses.

## Login

This server already has preconfigured users.
Therefore, to login please use one of these predefined credentials:

| Username | Email                    | Password | Roles       |
|----------|--------------------------|----------|-------------|
| viudes   | viudes@example.com       | viudes   | USER        |

## Postman

You may use the provided postman collections to try the authorization server endpoints and the registered clients.
The collections (for both JWT and Opaque tokens) can be found in the _postman_ folder.

## Persistent Configuration Store

The authorization server uses a persistent H2 (in-memory) storage for configuration and stored tokens.

You may have a look inside the data using the [H2 console](http://localhost:9000/h2-console).
Please use ```jdbc:h2:mem:authzserver``` as jdbc url and _sa_ as username, leave password empty.

## Customizations

This customized version contains an extended `user` object compared to the standard spring security `user` object.
The contents of id and access tokens and user info endpoint information is customized for extended user data as well.

Check the spring [authorization server reference docs](https://docs.spring.io/spring-authorization-server/docs/current/reference/html/guides/how-to-userinfo.html) for more information.

### Configure information returned to the userinfo endpoint

__com.example.spring.authorizationserver.config.AuthorizationServerConfig:__

```kotlin
@Configuration(proxyBeanMethods = false)
@Bean
@Order(Ordered.HIGHEST_PRECEDENCE)
@Throws(
    Exception::class
)
fun authorizationServerSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
    val userInfoMapper = Function { context: OidcUserInfoAuthenticationContext ->
        val authentication = context.getAuthentication<OidcUserInfoAuthenticationToken>()
        val principal = authentication.principal as JwtAuthenticationToken
        OidcUserInfo(principal.token.claims)
    }

    val authorizationServerConfigurer = OAuth2AuthorizationServerConfigurer()
    val endpointsMatcher = authorizationServerConfigurer.endpointsMatcher
    http.securityMatcher(endpointsMatcher)
        .authorizeHttpRequests(Customizer { authorize ->
            (authorize.anyRequest()).authenticated()
        }).csrf { csrf: CsrfConfigurer<HttpSecurity?> ->
            csrf.ignoringRequestMatchers(endpointsMatcher)
        }.apply(authorizationServerConfigurer)
    authorizationServerConfigurer.oidc { o: OidcConfigurer ->
        o
            .providerConfigurationEndpoint(Customizer.withDefaults())
            .clientRegistrationEndpoint(Customizer.withDefaults())
            .userInfoEndpoint { userInfo: OidcUserInfoEndpointConfigurer ->
                userInfo
                    .userInfoMapper(userInfoMapper)
            }
    }

    http
        .exceptionHandling { exceptions: ExceptionHandlingConfigurer<HttpSecurity?> ->
            exceptions
                .defaultAuthenticationEntryPointFor(
                    LoginUrlAuthenticationEntryPoint("/login"),
                    MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                )
        }
        .oauth2ResourceServer { resourceServer: OAuth2ResourceServerConfigurer<HttpSecurity?> ->
            resourceServer
                .jwt(Customizer.withDefaults())
        }
    return http.build()
}
```

### Customize id and access token contents

```kotlin
@Configuration
class JwtTokenCustomizerConfig {
    @Bean
    fun tokenCustomizer(userInfoService: OidcUserInfoService): OAuth2TokenCustomizer<JwtEncodingContext> {
        return OAuth2TokenCustomizer { context: JwtEncodingContext ->
            if (AuthorizationGrantType.CLIENT_CREDENTIALS != context.authorizationGrantType) {
                if (OidcParameterNames.ID_TOKEN == context.tokenType.value || OAuth2TokenType.ACCESS_TOKEN == context.tokenType) {
                    val userInfo = userInfoService.loadUser(
                        context.getPrincipal<Authentication>().name
                    )
                    context.claims.claims { claims: MutableMap<String?, Any?> -> claims.putAll(userInfo.claims) }
                    context.jwsHeader.type("jwt")
                }
            }
        }
    }
}

```

## Testing the Authorization Server

For testing this authorization server with client- or server applications please use the corresponding GitHub repository for [Custom Spring Authorization Server Samples](https://github.com/andifalk/custom-spring-authorization-server-samples).

This includes a demo OAuth client and resource server.

## Feedback

Any feedback on this project is highly appreciated.

Just email _andreas.falk(at)novatec-gmbh.de_ or contact me via Twitter (_@andifalk_).

## License

Apache 2.0 licensed

[1]:http://www.apache.org/licenses/LICENSE-2.0.txt

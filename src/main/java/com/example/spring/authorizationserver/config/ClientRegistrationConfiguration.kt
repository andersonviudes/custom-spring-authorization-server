package com.example.spring.authorizationserver.config

import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.oidc.OidcScopes
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings
import java.time.Duration
import java.util.List
import java.util.UUID

@Configuration
class ClientRegistrationConfiguration {
    @Bean
    fun registeredClientRepository(
        jdbcTemplate: JdbcTemplate?,
        passwordEncoder: PasswordEncoder
    ): RegisteredClientRepository {
        val redirectUris = redirectUris

        val demoClient = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId("demo-client")
            .clientSecret(passwordEncoder.encode("secret"))
            .clientAuthenticationMethods { methods: MutableSet<ClientAuthenticationMethod?> ->
                methods.addAll(
                    List.of(
                        ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                        ClientAuthenticationMethod.CLIENT_SECRET_POST,
                        ClientAuthenticationMethod.NONE
                    )
                )
            }
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .tokenSettings(
                TokenSettings.builder().accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                    .accessTokenTimeToLive(Duration.ofMinutes(15))
                    .authorizationCodeTimeToLive(Duration.ofMinutes(2)).build()
            )
            .redirectUris { uris: MutableSet<String> ->
                uris.addAll(redirectUris)
            }
            .scopes { scopes: MutableSet<String> ->
                scopes.addAll(
                    List.of(
                        OidcScopes.OPENID, OidcScopes.PROFILE, OidcScopes.EMAIL, "offline_access"
                    )
                )
            }
            .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build())
            .build()

        val demoClientPkce = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId("demo-client-pkce")
            .clientAuthenticationMethods { methods: MutableSet<ClientAuthenticationMethod?> ->
                methods.addAll(
                    List.of(
                        ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                        ClientAuthenticationMethod.CLIENT_SECRET_POST,
                        ClientAuthenticationMethod.NONE
                    )
                )
            }
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .tokenSettings(
                TokenSettings.builder().accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                    .accessTokenTimeToLive(Duration.ofMinutes(15))
                    .authorizationCodeTimeToLive(Duration.ofMinutes(2)).build()
            )
            .redirectUris { uris: MutableSet<String> ->
                uris.addAll(redirectUris)
            }
            .scopes { scopes: MutableSet<String> ->
                scopes.addAll(
                    List.of(
                        OidcScopes.OPENID, OidcScopes.PROFILE, OidcScopes.EMAIL, "offline_access"
                    )
                )
            }
            .clientSettings(ClientSettings.builder().requireProofKey(true).requireAuthorizationConsent(false).build())
            .build()

        val demoClientOpaque = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId("demo-client-opaque")
            .clientSecret(passwordEncoder.encode("secret"))
            .clientAuthenticationMethods { methods: MutableSet<ClientAuthenticationMethod?> ->
                methods.addAll(
                    List.of(
                        ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                        ClientAuthenticationMethod.CLIENT_SECRET_POST,
                        ClientAuthenticationMethod.NONE
                    )
                )
            }
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .tokenSettings(
                TokenSettings.builder().accessTokenFormat(OAuth2TokenFormat.REFERENCE)
                    .accessTokenTimeToLive(Duration.ofMinutes(15))
                    .authorizationCodeTimeToLive(Duration.ofMinutes(2)).build()
            )
            .redirectUris { uris: MutableSet<String> ->
                uris.addAll(redirectUris)
            }
            .scopes { scopes: MutableSet<String> ->
                scopes.addAll(
                    List.of(
                        OidcScopes.OPENID, OidcScopes.PROFILE, OidcScopes.EMAIL, "offline_access"
                    )
                )
            }
            .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build())
            .build()

        val demoClientPkceOpaque = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId("demo-client-pkce-opaque")
            .clientSecret(passwordEncoder.encode("secret"))
            .clientAuthenticationMethods { methods: MutableSet<ClientAuthenticationMethod?> ->
                methods.addAll(
                    List.of(
                        ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                        ClientAuthenticationMethod.CLIENT_SECRET_POST,
                        ClientAuthenticationMethod.NONE
                    )
                )
            }
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .tokenSettings(
                TokenSettings.builder().accessTokenFormat(OAuth2TokenFormat.REFERENCE)
                    .accessTokenTimeToLive(Duration.ofMinutes(15))
                    .authorizationCodeTimeToLive(Duration.ofMinutes(2)).build()
            )
            .redirectUris { uris: MutableSet<String> ->
                uris.addAll(redirectUris)
            }
            .scopes { scopes: MutableSet<String> ->
                scopes.addAll(
                    List.of(
                        OidcScopes.OPENID, OidcScopes.PROFILE, OidcScopes.EMAIL, "offline_access"
                    )
                )
            }
            .clientSettings(ClientSettings.builder().requireProofKey(true).requireAuthorizationConsent(false).build())
            .build()

        val registeredClientRepository = JdbcRegisteredClientRepository(jdbcTemplate)
        registeredClientRepository.save(demoClient)
        registeredClientRepository.save(demoClientPkce)
        registeredClientRepository.save(demoClientOpaque)
        registeredClientRepository.save(demoClientPkceOpaque)

        LOGGER.info("Registered OAuth2/OIDC clients")

        return registeredClientRepository
    }

    @Bean
    fun authorizationService(
        jdbcTemplate: JdbcTemplate?,
        registeredClientRepository: RegisteredClientRepository?
    ): OAuth2AuthorizationService {
        return JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository)
    }

    @Bean
    fun authorizationConsentService(
        jdbcTemplate: JdbcTemplate?,
        registeredClientRepository: RegisteredClientRepository?
    ): OAuth2AuthorizationConsentService {
        return JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository)
    }

    companion object {
        private val LOGGER: Logger = LoggerFactory.getLogger(ClientRegistrationConfiguration::class.java)

        private val redirectUris: Set<String>
            get() {
                val redirectUris: MutableSet<String> = HashSet()
                redirectUris.add("http://127.0.0.1:9095/client/callback")
                redirectUris.add("http://127.0.0.1:9095/client")
                redirectUris.add("http://127.0.0.1:9090/login/oauth2/code/spring")
                redirectUris.add("http://127.0.0.1:9095/client/login/oauth2/code/spring")
                redirectUris.add("http://localhost:9095/client/callback")
                redirectUris.add("http://localhost:9095/client")
                redirectUris.add("http://localhost:9090/login/oauth2/code/spring")
                redirectUris.add("http://localhost:9095/client/login/oauth2/code/spring")
                redirectUris.add("https://oauth.pstmn.io/v1/callback")
                return redirectUris
            }
    }
}

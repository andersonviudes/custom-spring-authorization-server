package com.example.authorizationserver.config

import com.example.authorizationserver.security.OidcUserInfoService
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer

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

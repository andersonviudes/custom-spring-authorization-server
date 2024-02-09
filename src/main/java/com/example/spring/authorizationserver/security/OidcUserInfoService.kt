package com.example.spring.authorizationserver.security

import com.example.spring.authorizationserver.user.User
import org.springframework.security.oauth2.core.oidc.OidcUserInfo
import org.springframework.stereotype.Service

@Service
class OidcUserInfoService(private val userDetailsService: AuthorizationServerUserDetailsService) {
    fun loadUser(username: String): OidcUserInfo {
        val user = userDetailsService.loadUserByUsername(username) as User
        return OidcUserInfo.builder()
            .subject(user.identifier.toString())
            .name(user.firstName + " " + user.lastName)
            .givenName(user.firstName)
            .familyName(user.lastName)
            .nickname(username)
            .preferredUsername(username)
            .profile("https://example.com/$username")
            .website("https://example.com")
            .email(user.email)
            .emailVerified(true)
            .claim("roles", user.roles)
            .zoneinfo("Europe/Berlin")
            .locale("de-DE")
            .updatedAt("1970-01-01T00:00:00Z")
            .build()
    }
}

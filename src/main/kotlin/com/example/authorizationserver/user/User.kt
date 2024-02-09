package com.example.authorizationserver.user

import com.fasterxml.jackson.annotation.JsonAutoDetect
import com.fasterxml.jackson.annotation.JsonIgnore
import com.fasterxml.jackson.annotation.JsonProperty
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.AuthorityUtils
import org.springframework.security.core.userdetails.UserDetails
import java.util.UUID
import java.util.stream.Collectors

@JsonAutoDetect
class User : UserDetails {
    var identifier: UUID? = null
    private var username: String? = null
    private var password: String? = null
    var firstName: String? = null
    var lastName: String? = null
    var email: String? = null

    var roles: Set<String> = HashSet()

    constructor()

    constructor(
        identifier: UUID?,
        username: String?,
        password: String?,
        firstName: String?,
        lastName: String?,
        email: String?,
        roles: Set<String>
    ) {
        this.identifier = identifier
        this.username = username
        this.password = password
        this.firstName = firstName
        this.lastName = lastName
        this.email = email
        this.roles = roles
    }

    @JsonProperty("username")
    override fun getUsername(): String {
        return username!!
    }

    @JsonIgnore
    override fun isAccountNonExpired(): Boolean {
        return true
    }

    @JsonIgnore
    override fun isAccountNonLocked(): Boolean {
        return true
    }

    @JsonIgnore
    override fun isCredentialsNonExpired(): Boolean {
        return true
    }

    @JsonIgnore
    override fun isEnabled(): Boolean {
        return true
    }

    override fun getAuthorities(): Collection<GrantedAuthority?> {
        return AuthorityUtils.commaSeparatedStringToAuthorityList(roles.stream().map { r: String -> "ROLE_$r" }
            .collect(Collectors.joining()))
    }

    fun setAuthorities(authorities: Collection<GrantedAuthority?>?) {}

    override fun getPassword(): String {
        return password!!
    }

    fun setUsername(username: String?) {
        this.username = username
    }

    fun setPassword(password: String?) {
        this.password = password
    }

    override fun toString(): String {
        return "User{" +
            "identifier=" + identifier +
            ", username='" + username + '\'' +
            ", password='" + password + '\'' +
            ", firstName='" + firstName + '\'' +
            ", lastName='" + lastName + '\'' +
            ", email='" + email + '\'' +
            ", roles=" + roles +
            "} " + super.toString()
    }
}

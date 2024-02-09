package com.example.authorizationserver.security

import com.example.authorizationserver.user.User
import jakarta.annotation.PostConstruct
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service
import java.util.UUID

@Service
class AuthorizationServerUserDetailsService(private val passwordEncoder: PasswordEncoder) : UserDetailsService {
    private val users: MutableMap<String, User> = HashMap()

    @PostConstruct
    fun initUsers() {
        val bRoles: MutableSet<String> = HashSet()
        bRoles.add("USER")
        val bViudes = User(
            UUID.fromString(VIUDES_ID), "viudes", passwordEncoder.encode("viudes"),
            "Viudes", "Viudes", "viudes@example.com", bRoles
        )
        val cKentRoles: MutableSet<String> = HashSet()
        cKentRoles.add("USER")
        users["viudes"] = bViudes

        LOGGER.info("Initialized users {}, {} and {}", bViudes)
    }

    @Throws(UsernameNotFoundException::class)
    override fun loadUserByUsername(username: String): UserDetails {
        if (users.containsKey(username)) {
            LOGGER.info("Found user for {}", username)
            return users[username]!!
        } else {
            LOGGER.warn("No user found for {}", username)
            throw UsernameNotFoundException("No user found for $username")
        }
    }

    companion object {
        const val VIUDES_ID: String = "c52bf7db-db55-4f89-ac53-82b40e8c57c2"

        private val LOGGER: Logger = LoggerFactory.getLogger(AuthorizationServerUserDetailsService::class.java)
    }
}

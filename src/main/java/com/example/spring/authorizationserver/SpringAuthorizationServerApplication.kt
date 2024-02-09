package com.example.spring.authorizationserver

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class SpringAuthorizationServerApplication

fun main(args: Array<String>) {
    runApplication<SpringAuthorizationServerApplication>(*args)
}

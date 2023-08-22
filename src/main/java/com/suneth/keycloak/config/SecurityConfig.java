package com.suneth.keycloak.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

/*
Spring Security configuration class for securing an application using
Keycloak as an OAuth 2.0 resource server with JSON Web Tokens (JWTs).
*/

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
/*
@RequiredArgsConstructor is a Lombok annotation that automatically generates a constructor injecting the final fields.
*/
public class SecurityConfig {
    private final JwtAuthConverter jwtAuthConverter;

    // This bean configures the security filter chain
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        /*.csrf().disable() disables Cross-Site Request Forgery (CSRF) protection.

         * .authorizeHttpRequests().anyRequest().authenticated() configures the authorization rules, allowing any request to be authenticated.

         * .oauth2ResourceServer().jwt().jwtAuthenticationConverter(jwtAuthConverter) configures the OAuth 2.0 resource server using JWTs.
           It specifies the jwtAuthConverter bean to convert JWTs into authentication objects.

         * .sessionManagement().sessionCreationPolicy(STATELESS) configures the session management to be stateless,
            meaning that the application won't create or use HTTP sessions.
        */
        httpSecurity
                .csrf()
                .disable()
                .authorizeHttpRequests()
                .anyRequest()
                .authenticated();

        // Configures the JWT authentication converter
        httpSecurity
                .oauth2ResourceServer()
                .jwt()
                .jwtAuthenticationConverter(jwtAuthConverter);

        // Configures the session management to be stateless
        httpSecurity
                .sessionManagement()
                .sessionCreationPolicy(STATELESS);

        return httpSecurity.build();
    }
}

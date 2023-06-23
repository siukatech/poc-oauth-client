package com.siukatech.poc.oauthclient.security.config;

import com.siukatech.poc.oauthclient.security.converter.KeycloakJwtAuthenticationConverter;
import com.siukatech.poc.oauthclient.security.handler.KeycloakLogoutHandler;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class WebSecurityConfig {

    private final KeycloakLogoutHandler keycloakLogoutHandler;
    private final OAuth2ResourceServerProperties oAuth2ResourceServerProperties;
    private final KeycloakJwtAuthenticationConverter keycloakJwtAuthenticationConverter;

    public WebSecurityConfig(KeycloakLogoutHandler keycloakLogoutHandler
            , OAuth2ResourceServerProperties oAuth2ResourceServerProperties, KeycloakJwtAuthenticationConverter keycloakJwtAuthenticationConverter) {
        this.keycloakLogoutHandler = keycloakLogoutHandler;
        this.oAuth2ResourceServerProperties = oAuth2ResourceServerProperties;
        this.keycloakJwtAuthenticationConverter = keycloakJwtAuthenticationConverter;
    }

    @Bean
    protected SessionAuthenticationStrategy sessionAuthenticationStrategy() {
        return new RegisterSessionAuthenticationStrategy(new SessionRegistryImpl());
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.authorizeHttpRequests(requests -> requests.requestMatchers("/", "/login")
                .permitAll()
                .anyRequest().fullyAuthenticated()
        )
//                .antMatchers("/customers*")
//                .hasRole("USER")
//                .anyRequest()
//                .permitAll()
        ;
        http.oauth2Login();
        http.logout()
                .addLogoutHandler(keycloakLogoutHandler)
                .logoutSuccessUrl("/login")
                .permitAll()
        ;
        //http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
        http.oauth2ResourceServer()
                .jwt()
                .jwtAuthenticationConverter(keycloakJwtAuthenticationConverter)
        ;
        return http.build();
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        NimbusJwtDecoder jwtDecoder = JwtDecoders.fromOidcIssuerLocation(
                oAuth2ResourceServerProperties.getJwt().getIssuerUri()
        );
        OAuth2TokenValidator<Jwt> withIssuerJwtTokenValidator = JwtValidators.createDefaultWithIssuer(
                oAuth2ResourceServerProperties.getJwt().getIssuerUri()
        );
        OAuth2TokenValidator<Jwt> jwtDelegatingOAuth2TokenValidator = new DelegatingOAuth2TokenValidator<Jwt>(withIssuerJwtTokenValidator);
        jwtDecoder.setJwtValidator(jwtDelegatingOAuth2TokenValidator);
        return jwtDecoder;
    }


}

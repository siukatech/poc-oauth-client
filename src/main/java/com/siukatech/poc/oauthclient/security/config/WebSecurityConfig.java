package com.siukatech.poc.oauthclient.security.config;

import com.siukatech.poc.oauthclient.security.converter.KeycloakJwtAuthenticationConverter;
import com.siukatech.poc.oauthclient.security.converter.OpaqueTokenAuthenticationConverterImpl;
import com.siukatech.poc.oauthclient.security.handler.KeycloakLogoutHandler;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.introspection.SpringOpaqueTokenIntrospector;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class WebSecurityConfig {

    private final OAuth2ResourceServerProperties oAuth2ResourceServerProperties;
    private final KeycloakLogoutHandler keycloakLogoutHandler;
    private final KeycloakJwtAuthenticationConverter keycloakJwtAuthenticationConverter;
//    private final OpaqueTokenAuthenticationConverter opaqueTokenAuthenticationConverter;

    public WebSecurityConfig(OAuth2ResourceServerProperties oAuth2ResourceServerProperties
            , KeycloakLogoutHandler keycloakLogoutHandler
            , KeycloakJwtAuthenticationConverter keycloakJwtAuthenticationConverter
//            , OpaqueTokenAuthenticationConverter opaqueTokenAuthenticationConverter
    ) {
        this.oAuth2ResourceServerProperties = oAuth2ResourceServerProperties;
        this.keycloakLogoutHandler = keycloakLogoutHandler;
        this.keycloakJwtAuthenticationConverter = keycloakJwtAuthenticationConverter;
//        this.opaqueTokenAuthenticationConverter = opaqueTokenAuthenticationConverter;
    }

    @Bean
    protected SessionAuthenticationStrategy sessionAuthenticationStrategy() {
        return new RegisterSessionAuthenticationStrategy(new SessionRegistryImpl());
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//        http.csrf().disable();
        http.csrf(Customizer.withDefaults());
        http.authorizeHttpRequests(requests -> requests
                .requestMatchers("/", "/login", "/error")
                .permitAll()
                .anyRequest().fullyAuthenticated()
        )
//                .antMatchers("/customers*")
//                .hasRole("USER")
//                .anyRequest()
//                .permitAll()
        ;
//        http.oauth2Login();
        http.oauth2Login(Customizer.withDefaults())
//                .oauth2Login(oauth2LoginConfigurer -> oauth2LoginConfigurer.)
        ;
//        http.logout()
//                .addLogoutHandler(keycloakLogoutHandler)
//                .logoutSuccessUrl("/")
//                .permitAll()
//        ;
        http.logout(logoutConfigurer ->
                logoutConfigurer
                        .addLogoutHandler(keycloakLogoutHandler)
                        .logoutSuccessUrl("/")
                        .permitAll()
        );
//        //http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
//        http.oauth2ResourceServer()
//                .jwt()
//                .jwtAuthenticationConverter(keycloakJwtAuthenticationConverter)
//        ;
        //
        //
        // Exception:
        // Spring Security only supports JWTs or Opaque Tokens, not both at the same time.
        // Reference:
        // https://stackoverflow.com/questions/73212714/can-i-use-both-introspection-server-and-local-check-for-authorize-token-spring
        //
        http.oauth2ResourceServer(resourceServerConfigurer -> resourceServerConfigurer
//                .jwt(jwtConfigurer -> jwtConfigurer
//                        .jwtAuthenticationConverter(keycloakJwtAuthenticationConverter)
//                )
                .opaqueToken(Customizer.withDefaults())
                .opaqueToken(opaqueTokenConfigurer -> opaqueTokenConfigurer
                        .authenticationConverter(opaqueTokenAuthenticationConverter())
                )
        );
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

    @Bean
    public OpaqueTokenAuthenticationConverter opaqueTokenAuthenticationConverter() {
        OpaqueTokenAuthenticationConverter opaqueTokenAuthenticationConverter = new OpaqueTokenAuthenticationConverterImpl(jwtDecoder(), keycloakJwtAuthenticationConverter);
        return opaqueTokenAuthenticationConverter;
    }

}

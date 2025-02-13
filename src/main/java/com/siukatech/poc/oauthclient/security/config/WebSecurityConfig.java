package com.siukatech.poc.oauthclient.security.config;

import com.siukatech.poc.oauthclient.security.converter.KeycloakJwtAuthenticationConverter;
import com.siukatech.poc.oauthclient.security.converter.OpaqueTokenAuthenticationConverterImpl;
import com.siukatech.poc.oauthclient.security.handler.KeycloakLogoutHandler;
import lombok.extern.slf4j.Slf4j;
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
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.springframework.security.oauth2.jwt.JwtClaimNames.AUD;

@Slf4j
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class WebSecurityConfig {

//    private final OAuth2ResourceServerProperties oAuth2ResourceServerProperties;
//    private final KeycloakLogoutHandler keycloakLogoutHandler;
//    private final KeycloakJwtAuthenticationConverter keycloakJwtAuthenticationConverter;
////    private final OpaqueTokenAuthenticationConverter opaqueTokenAuthenticationConverter;
//
//    public WebSecurityConfig(OAuth2ResourceServerProperties oAuth2ResourceServerProperties
//            , KeycloakLogoutHandler keycloakLogoutHandler
//            , KeycloakJwtAuthenticationConverter keycloakJwtAuthenticationConverter
////            , OpaqueTokenAuthenticationConverter opaqueTokenAuthenticationConverter
//    ) {
//        this.oAuth2ResourceServerProperties = oAuth2ResourceServerProperties;
//        this.keycloakLogoutHandler = keycloakLogoutHandler;
//        this.keycloakJwtAuthenticationConverter = keycloakJwtAuthenticationConverter;
////        this.opaqueTokenAuthenticationConverter = opaqueTokenAuthenticationConverter;
//    }


    @Bean
    protected SessionAuthenticationStrategy sessionAuthenticationStrategy() {
        return new RegisterSessionAuthenticationStrategy(new SessionRegistryImpl());
    }

    @Bean
    public SecurityFilterChain filterChain(
            HttpSecurity http
            , JwtDecoder jwtDecoder
            , KeycloakLogoutHandler keycloakLogoutHandler
            , KeycloakJwtAuthenticationConverter keycloakJwtAuthenticationConverter
            , OpaqueTokenAuthenticationConverter opaqueTokenAuthenticationConverter
    ) throws Exception {
//        http.csrf().disable();
        http.csrf(Customizer.withDefaults());

        http.authorizeHttpRequests(
                authorizeHttpRequest -> authorizeHttpRequest
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
        http.oauth2ResourceServer(
                resourceServerConfigurer -> resourceServerConfigurer
                .jwt(jwtConfigurer -> jwtConfigurer
                        .jwtAuthenticationConverter(keycloakJwtAuthenticationConverter)
                        .decoder(jwtDecoder)
                )
//                .opaqueToken(Customizer.withDefaults())
//                .opaqueToken(opaqueTokenConfigurer -> opaqueTokenConfigurer
//                        .authenticationConverter(opaqueTokenAuthenticationConverter)
//                )
        );

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

        return http.build();
    }

    @Bean
    public JwtDecoder jwtDecoder(
            OAuth2ResourceServerProperties oAuth2ResourceServerProperties
//            , OAuth2ResourceServerExtProp oAuth2ResourceServerExtProp
    ) {
        String issuerUri = oAuth2ResourceServerProperties.getJwt().getIssuerUri();
        NimbusJwtDecoder jwtDecoder = JwtDecoders.fromOidcIssuerLocation(issuerUri);
        List<OAuth2TokenValidator<Jwt>> oAuth2TokenValidatorList = new ArrayList<>();
        OAuth2TokenValidator<Jwt> withIssuerJwtTokenValidator = JwtValidators.createDefaultWithIssuer(issuerUri);
        oAuth2TokenValidatorList.add(withIssuerJwtTokenValidator);
        if (oAuth2ResourceServerProperties.getJwt().getAudiences() != null) {
            // Reference:
            // https://stackoverflow.com/a/78144309
            OAuth2TokenValidator<Jwt> withAudiencesValidator = new JwtClaimValidator<List<String>>(AUD
                    , aud -> {
                log.debug("jwtDecoder - withAudiencesValidator - aud 1: [{}]"
                        + ", oAuth2ResourceServerProperties.getJwt.getAudiences: [{}]"
                        , aud
                        , oAuth2ResourceServerProperties.getJwt().getAudiences()
                );
                List<String> audList = new ArrayList<>(aud);
                audList.retainAll(oAuth2ResourceServerProperties.getJwt().getAudiences());
                //
//                List<String> list1 = new ArrayList<>(); list1.add("a"); list1.add("b"); list1.add("c"); list1.add("d");
//                List<String> list2 = new ArrayList<>(); list2.add("a"); list2.add("c"); list2.add("x"); list2.add("y");
//                list1.retainAll(list2);
//                log.debug("jwtDecoder - withAudiencesValidator - list1: [{}]", list1);
                //
                // list1.retainAll(list2) will remove the item that does not exist in list2, for example:
                // list1 (a, b, c, d), list2 (a, c, x, y)
                // After the retainAll, list1 becomes list1 (a, c)
                // As a result, (!audList.isEmpty) means Jwt token's audiences (aud) exist in the yaml's audiences
                boolean result = !audList.isEmpty();
                log.debug("jwtDecoder - withAudiencesValidator - result: [{}], aud 2: [{}]"
                        + ", oAuth2ResourceServerProperties.getJwt.getAudiences: [{}]"
                        + ", audList: [{}]"
                        , result
                        , aud
                        , oAuth2ResourceServerProperties.getJwt().getAudiences()
                        , audList);
                return result;
            });
            oAuth2TokenValidatorList.add(withAudiencesValidator);
        }
        OAuth2TokenValidator<Jwt> jwtDelegatingOAuth2TokenValidator
                = new DelegatingOAuth2TokenValidator<>(
//                        withIssuerJwtTokenValidator, withAudiencesValidator
                oAuth2TokenValidatorList.toArray(OAuth2TokenValidator[]::new)
        );
        jwtDecoder.setJwtValidator(jwtDelegatingOAuth2TokenValidator);
        return jwtDecoder;
    }

    @Bean
    public OpaqueTokenAuthenticationConverter opaqueTokenAuthenticationConverter(
            JwtDecoder jwtDecoder
            , KeycloakJwtAuthenticationConverter keycloakJwtAuthenticationConverter
    ) {
        OpaqueTokenAuthenticationConverter opaqueTokenAuthenticationConverter
                = new OpaqueTokenAuthenticationConverterImpl(jwtDecoder, keycloakJwtAuthenticationConverter);
        return opaqueTokenAuthenticationConverter;
    }

}

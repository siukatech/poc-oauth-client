package com.siukatech.poc.oauthclient.security.converter;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenAuthenticationConverter;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Slf4j
//@Component
public class OpaqueTokenAuthenticationConverterImpl implements OpaqueTokenAuthenticationConverter {

    private final JwtDecoder jwtDecoder;
    private final KeycloakJwtAuthenticationConverter keycloakJwtAuthenticationConverter;
    public OpaqueTokenAuthenticationConverterImpl(JwtDecoder jwtDecoder
            , KeycloakJwtAuthenticationConverter keycloakJwtAuthenticationConverter) {
        this.jwtDecoder = jwtDecoder;
        this.keycloakJwtAuthenticationConverter = keycloakJwtAuthenticationConverter;
    }
    @Override
    public Authentication convert(String introspectedToken, OAuth2AuthenticatedPrincipal authenticatedPrincipal) {
        log.debug("convert - 1");

        Jwt source = jwtDecoder.decode(introspectedToken);
        log.debug("convert - source: [{}]", source);

        return keycloakJwtAuthenticationConverter.convert(source);
    }
}

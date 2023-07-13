package com.siukatech.poc.oauthclient.security.converter;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;

public interface KeycloakJwtAuthenticationConverter extends Converter<Jwt, AbstractAuthenticationToken> {
}

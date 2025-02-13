package com.siukatech.poc.oauthclient.security.converter;

import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Slf4j
@Component
@ConditionalOnProperty(value = "keycloak.jwt.auth.converter", havingValue = "1", matchIfMissing = true)
public class KeycloakJwtAuthenticationConverterImpl implements KeycloakJwtAuthenticationConverter {

    @Override
    public AbstractAuthenticationToken convert(Jwt source) {
        log.debug("convert - 1");
//        return new UsernamePasswordAuthenticationToken(userDetails, "NA", convertedAuthorities);
//        return null;
        String loginId = source.getClaimAsString(StandardClaimNames.PREFERRED_USERNAME);
        String tokenValue = source.getTokenValue();
        List<GrantedAuthority> convertedAuthorities = new ArrayList<>();
        UserDetails userDetails = new User(loginId, "null", convertedAuthorities);
        UsernamePasswordAuthenticationToken authenticationToken
                = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
        return authenticationToken;
    }

//    @Override
//    public <U> Converter<Jwt, U> andThen(Converter<? super AbstractAuthenticationToken, ? extends U> after) {
//        return Converter.super.andThen(after);
//    }


}

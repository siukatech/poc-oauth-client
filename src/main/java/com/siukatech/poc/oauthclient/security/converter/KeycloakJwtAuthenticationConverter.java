package com.siukatech.poc.oauthclient.security.converter;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
public class KeycloakJwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {
    @Override
    public AbstractAuthenticationToken convert(Jwt source) {
//        return new UsernamePasswordAuthenticationToken(userDetails, "NA", convertedAuthorities);
//        return null;
        List<GrantedAuthority> convertedAuthorities = new ArrayList<>();
        UserDetails userDetails = new User(source.getSubject(), null, convertedAuthorities);
        UsernamePasswordAuthenticationToken authenticationToken
                = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
        return authenticationToken;
    }

//    @Override
//    public <U> Converter<Jwt, U> andThen(Converter<? super AbstractAuthenticationToken, ? extends U> after) {
//        return Converter.super.andThen(after);
//    }


}

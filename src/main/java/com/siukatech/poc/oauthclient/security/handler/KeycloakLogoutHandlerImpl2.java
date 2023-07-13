package com.siukatech.poc.oauthclient.security.handler;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

@Slf4j
@ConditionalOnProperty(value = "keycloak.jwt.auth.handler", havingValue = "2")
@Component
public class KeycloakLogoutHandlerImpl2 implements KeycloakLogoutHandler {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    //    private final RestTemplate restTemplate;
    private RestTemplate restTemplate;

    //    public KeycloakLogoutHandler(RestTemplate restTemplate) {
//        this.restTemplate = new RestTemplate();
//    }
    public KeycloakLogoutHandlerImpl2() {
        this.restTemplate = new RestTemplate();
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        logger.debug("logout - authentication: [" + (authentication == null ? "NULL" : authentication) + "]");
        logoutFromKeycloak((OidcUser) authentication.getPrincipal());
    }

    private void logoutFromKeycloak(OidcUser user) {
        String endSessionEndpoint = user.getIssuer() + "/protocol/openid-connect/logout";
        UriComponentsBuilder builder = UriComponentsBuilder
                .fromUriString(endSessionEndpoint)
                .queryParam("id_token_hint", user.getIdToken().getTokenValue());

        ResponseEntity<String> logoutResponse = restTemplate.getForEntity(
                builder.toUriString(), String.class);
        if (logoutResponse.getStatusCode().is2xxSuccessful()) {
            logger.info("logoutFromKeycloak - 2 - Successfully logged out from Keycloak");
        } else {
            logger.error("logoutFromKeycloak - 2 - Could not propagate logout to Keycloak");
        }
    }

}
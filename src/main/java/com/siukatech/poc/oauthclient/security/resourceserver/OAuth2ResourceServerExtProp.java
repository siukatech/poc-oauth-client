package com.siukatech.poc.oauthclient.security.resourceserver;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.HashMap;
import java.util.Map;

@Slf4j
@Data
@Configuration
//@ConfigurationProperties("spring.security.oauth2.resource-server")
public class OAuth2ResourceServerExtProp implements InitializingBean {
    private Map<String, OAuth2ResourceServerProperties.Jwt> jwt = new HashMap<>();
    private Map<String, Opaquetoken> opaquetoken = new HashMap<>();

    @Override
    public void afterPropertiesSet() throws Exception {
        log.info("afterPropertiesSet - jwt: [{}], opaquetoken: [{}]", jwt, opaquetoken);
    }

    @Data
    public static class Opaquetoken extends OAuth2ResourceServerProperties.Opaquetoken {
        private String issuerUri;
    }

}

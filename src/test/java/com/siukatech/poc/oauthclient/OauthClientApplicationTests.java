package com.siukatech.poc.oauthclient;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest({
		"client-id=XXX"
		, "client-secret=XXX"
		, "client-realm=oauth-client-realm"
		, "oauth2.client.keycloak=http://localhost:38180"
		, "spring.profiles.active=dev"
})
class OauthClientApplicationTests {

	@Test
	void contextLoads() {
	}

}

package uk.gov.di.authentication.services;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.shared.services.RemoteJwksService;
import uk.gov.di.authentication.sharedtest.extensions.JwksExtension;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class RemoteJwksServiceIntegrationTest {
    @RegisterExtension private static final JwksExtension jwksExtension = new JwksExtension();
    private static final String TEST_KEY_ID = "test-key-id";
    private static RemoteJwksService remoteJwksService;
    private static JWK testJwk;

    @BeforeAll
    static void beforeAll() throws Exception {
        var ecKeyPair = new ECKeyGenerator(Curve.P_256).keyID(TEST_KEY_ID).generate();
        testJwk = ecKeyPair.toPublicJWK();
        jwksExtension.init(new JWKSet(testJwk));
        remoteJwksService = new RemoteJwksService(jwksExtension.getJwksUrl());
    }

    @Test
    void shouldRetrieveKeyFromJwksUrl() throws KeySourceException {
        var actualJwk = remoteJwksService.retrieveJwkFromURLWithKeyId(TEST_KEY_ID);
        assertThat(actualJwk, equalTo(testJwk));
    }

    @Test
    void shouldThrowExceptionIfKeyNotFound() {
        assertThrows(
                KeySourceException.class,
                () -> remoteJwksService.retrieveJwkFromURLWithKeyId("not-a-key-id"));
    }
}

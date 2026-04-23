package uk.gov.di.authentication.accountdata.services;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.junit.jupiter.api.Test;

import java.net.URL;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class RemoteJwksServiceTest {

    private static final String KEY_ID = "test-key-id";

    @SuppressWarnings("unchecked")
    private final JWKSource<SecurityContext> jwkSource = mock(JWKSource.class);

    private final RemoteJwksService service = new RemoteJwksService(jwkSource, dummyUrl());

    @Test
    void shouldReturnJwkWhenKeyIdMatches() throws Exception {
        var ecKey =
                new ECKeyGenerator(Curve.P_256)
                        .keyID(KEY_ID)
                        .algorithm(JWSAlgorithm.ES256)
                        .generate();

        when(jwkSource.get(any(JWKSelector.class), isNull()))
                .thenReturn(List.of(ecKey.toPublicJWK()));

        var result = service.retrieveJwkFromURLWithKeyId(KEY_ID);

        assertTrue(result.isSuccess());
        assertEquals(KEY_ID, result.getSuccess().getKeyID());
    }

    @Test
    void shouldReturnFailureWhenNoMatchingKeyFound() throws Exception {
        when(jwkSource.get(any(JWKSelector.class), isNull()))
                .thenReturn(Collections.<JWK>emptyList());

        var result = service.retrieveJwkFromURLWithKeyId(KEY_ID);

        assertTrue(result.isFailure());
        assertEquals("No JWK found with matching id", result.getFailure());
    }

    @Test
    void shouldReturnFailureWhenKeySourceExceptionThrown() throws Exception {
        when(jwkSource.get(any(JWKSelector.class), isNull()))
                .thenThrow(new KeySourceException("connection refused"));

        var result = service.retrieveJwkFromURLWithKeyId(KEY_ID);

        assertTrue(result.isFailure());
        assertTrue(result.getFailure().startsWith("Error retrieving jwks key"));
    }

    private static URL dummyUrl() {
        try {
            return new URL("https://example.com/.well-known/jwks.json");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}

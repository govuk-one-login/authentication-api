package uk.gov.di.authentication.frontendapi.services;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import uk.gov.di.authentication.frontendapi.entity.JwksServiceFailureReason;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class RemoteJwksServiceTest {
    private RemoteJwksService remoteJwksService;
    private static final ConfigurationService configurationService =
            mock(ConfigurationService.class);
    private static final HttpClient httpClient = mock(HttpClient.class);
    private static final String TEST_JWKS_URL = "https://test-jwks.url";
    private static final String TEST_VALID_JWKS =
            """
                    {
                      "keys": [
                        {
                          "kty": "RSA",
                          "e": "AQAB",
                          "use": "enc",
                          "alg": "RS256",
                          "n": "modulus",
                          "kid": "key1rsa"
                        },
                        {
                          "kty": "EC",
                          "use": "sig",
                          "crv": "P-256",
                          "x": "UPvU5NPmELrWiWSMVfDD7G8u3EJYryqPIZ46W9MAlRc",
                          "y": "r77F2-KPhpvTIGEWgt5SmavSvBUHCqWUxD6RG_FJHVk",
                          "alg": "ES256",
                          "kid": "key2ec"
                        }
                      ]
                    }""";

    @BeforeAll
    static void setUp() {
        when(configurationService.getRemoteJwksServiceCallTimeout()).thenReturn(1000L);
    }

    @BeforeEach
    void beforeEach() {
        Mockito.reset(httpClient);
        remoteJwksService = new RemoteJwksService(configurationService, TEST_JWKS_URL, httpClient);
    }

    @Test
    void shouldReturnIOFailureErrorAfterExceedingMaxRetries()
            throws IOException, InterruptedException {
        when(httpClient.send(any(), any()))
                .thenThrow(new IOException(), new IOException(), new IOException());

        var result = remoteJwksService.getJwkByKeyType(KeyType.EC);

        assertEquals(JwksServiceFailureReason.IO_FAILURE, result.getFailure());
    }

    @Test
    void shouldReturnInterruptedFailureErrorAfterExceedingMaxRetries()
            throws IOException, InterruptedException {
        when(httpClient.send(any(), any()))
                .thenThrow(
                        new InterruptedException(),
                        new InterruptedException(),
                        new InterruptedException());

        var result = remoteJwksService.getJwkByKeyType(KeyType.EC);

        assertEquals(JwksServiceFailureReason.INTERRUPTED_FAILURE, result.getFailure());
    }

    @Test
    void shouldReturnSuccessfulResponseAfterRetryingBelowMaxAttempts()
            throws IOException, InterruptedException {
        var httpResponse = mock(HttpResponse.class);
        when(httpClient.send(any(), any()))
                .thenThrow(new InterruptedException(), new IOException())
                .thenReturn(httpResponse);
        when(httpResponse.body()).thenReturn(TEST_VALID_JWKS);

        var result = remoteJwksService.getJwkByKeyType(KeyType.EC);

        assertInstanceOf(JWK.class, result.getSuccess());
    }
}

package uk.gov.di.authentication.frontendapi.services;

import com.nimbusds.jose.jwk.KeyType;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import uk.gov.di.authentication.frontendapi.entity.JwksServiceFailureReason;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.io.IOException;
import java.net.http.HttpClient;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class RemoteJwksServiceTest {
    private RemoteJwksService remoteJwksService;
    private static final ConfigurationService configurationService =
            mock(ConfigurationService.class);
    private static final HttpClient httpClient = mock(HttpClient.class);

    private static final String TEST_JWKS_URL = "https://test-jwks.url";

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
    void shouldReturnIOFailureError() throws IOException, InterruptedException {
        when(httpClient.send(any(), any())).thenThrow(new IOException());

        var result = remoteJwksService.getJwkByKeyType(KeyType.EC);

        assertEquals(JwksServiceFailureReason.IO_FAILURE, result.getFailure());
    }

    @Test
    void shouldReturnInterruptedFailureError() throws IOException, InterruptedException {
        when(httpClient.send(any(), any())).thenThrow(new InterruptedException());

        var result = remoteJwksService.getJwkByKeyType(KeyType.EC);

        assertEquals(JwksServiceFailureReason.INTERRUPTED_FAILURE, result.getFailure());
    }
}

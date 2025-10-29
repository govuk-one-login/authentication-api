package uk.gov.di.authentication.shared.helpers;

import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.util.ResourceRetriever;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.net.MalformedURLException;
import java.net.URL;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

public class JwksHelperTest {
    private AutoCloseable mocks;
    @Mock private ConfigurationService configurationService;

    @BeforeEach
    void setUp() throws MalformedURLException {
        mocks = MockitoAnnotations.openMocks(this);
        when(configurationService.isIpvJwksCallEnabled()).thenReturn(true);
        when(configurationService.getIpvJwksUrl()).thenReturn(new URL("https://example.com/jwks"));
        when(configurationService.isStubbedEnvironment()).thenReturn(false);
    }

    @AfterEach
    void tearDown() throws Exception {
        mocks.close();
    }

    @Test
    void shouldReturnNullWhenIpvJwksCallEnabledIsFalse() throws MalformedURLException {
        // arrange
        when(configurationService.isIpvJwksCallEnabled()).thenReturn(false);

        // act
        var result = JwksHelper.getJwkSource(configurationService);

        // assert
        assertNull(result);
    }

    @Test
    void shouldReturnNullWhenIpvJwksUrlIsNull() throws MalformedURLException {
        // arrange
        when(configurationService.getIpvJwksUrl()).thenReturn(null);

        // act
        var result = JwksHelper.getJwkSource(configurationService);

        // assert
        assertNull(result);
    }

    @Test
    void shouldUseCustomResourceRetrieverWhenStubbedEnvironmentIsTrue()
            throws MalformedURLException {
        // arrange
        when(configurationService.isStubbedEnvironment()).thenReturn(true);

        try (MockedStatic<JWKSourceBuilder> spiedBuilder =
                mockStatic(JWKSourceBuilder.class, CALLS_REAL_METHODS)) {
            // act
            JwksHelper.getJwkSource(configurationService);

            // assert
            spiedBuilder.verify(
                    () ->
                            JWKSourceBuilder.create(
                                    eq(new URL("https://example.com/jwks")),
                                    any(ResourceRetriever.class)));
        }
    }

    @Test
    void shouldUseDefaultResourceRetrieverWhenStubbedEnvironmentIsFalse()
            throws MalformedURLException {
        // arrange
        when(configurationService.isStubbedEnvironment()).thenReturn(false);

        try (MockedStatic<JWKSourceBuilder> spiedBuilder =
                mockStatic(JWKSourceBuilder.class, CALLS_REAL_METHODS)) {
            // act
            JwksHelper.getJwkSource(configurationService);

            // assert
            spiedBuilder.verify(
                    () -> JWKSourceBuilder.create(eq(new URL("https://example.com/jwks"))));
        }
    }
}

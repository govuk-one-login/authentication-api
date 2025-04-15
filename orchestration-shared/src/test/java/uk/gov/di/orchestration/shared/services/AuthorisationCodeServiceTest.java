package uk.gov.di.orchestration.shared.services;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.orchestration.shared.entity.AuthCodeExchangeData;
import uk.gov.di.orchestration.shared.serialization.Json;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.startsWith;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AuthorisationCodeServiceTest {
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final RedisConnectionService redisConnectionService =
            mock(RedisConnectionService.class);
    private final Json objectMapper = SerializationService.getInstance();
    private AuthorisationCodeService authCodeService;

    @BeforeEach
    void setup() {
        when(configurationService.getAuthCodeExpiry()).thenReturn(123L);
        authCodeService =
                new AuthorisationCodeService(
                        configurationService, redisConnectionService, objectMapper);
    }

    @Test
    void shouldSaveToRedisWhenGeneratingAuthCode() throws Json.JsonException {
        authCodeService.generateAndSaveAuthorisationCode(
                "test-client-id", "test-client-session", "test@email.com", 12345L);

        AuthCodeExchangeData expectedExchangeData =
                new AuthCodeExchangeData()
                        .setClientId("test-client-id")
                        .setClientSessionId("test-client-session")
                        .setEmail("test@email.com")
                        .setAuthTime(12345L);
        String expectedJson = objectMapper.writeValueAsString(expectedExchangeData);
        verify(redisConnectionService)
                .saveWithExpiry(startsWith("auth-code-"), eq(expectedJson), eq(123L));
    }
}

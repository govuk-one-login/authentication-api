package uk.gov.di.authentication.oidc.services;

import com.nimbusds.oauth2.sdk.id.State;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.orchestration.shared.services.RedisConnectionService;

import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AuthenticationAuthorizationServiceTest {
    private final RedisConnectionService redisConnectionService =
            mock(RedisConnectionService.class);
    private AuthenticationAuthorizationService authService;
    private static final State REDIS_STORED_STATE = new State();
    private static final String SESSION_ID = "a-session-id";
    private static final String EXAMPLE_AUTH_CODE = "any-text-will-do";

    @BeforeEach
    void setUp() {
        when(redisConnectionService.getValue(anyString()))
                .thenReturn(REDIS_STORED_STATE.getValue());
        authService = new AuthenticationAuthorizationService(redisConnectionService);
    }

    @Test
    void shouldValidateRequestWithValidParams() {
        Map<String, String> queryParams = new HashMap<>();
        queryParams.put("state", REDIS_STORED_STATE.getValue());
        queryParams.put("code", EXAMPLE_AUTH_CODE);

        boolean result = authService.validateRequest(queryParams, SESSION_ID);

        assertThat(result, is(true));
        verify(redisConnectionService)
                .getValue(
                        AuthenticationAuthorizationService.AUTHENTICATION_STATE_STORAGE_PREFIX
                                + SESSION_ID);
    }

    @Test
    void shouldReturnFalseWhenNoQueryParametersPresent() {
        Map<String, String> queryParams = new HashMap<>();

        boolean result = authService.validateRequest(queryParams, SESSION_ID);

        assertThat(result, is(false));
        verify(redisConnectionService, never()).getValue(anyString());
    }

    @Test
    void shouldReturnFalseWhenErrorParamPresent() {
        Map<String, String> queryParams = new HashMap<>();
        queryParams.put("error", "some-error");

        boolean result = authService.validateRequest(queryParams, SESSION_ID);

        assertThat(result, is(false));
        verify(redisConnectionService, never()).getValue(anyString());
    }

    @Test
    void shouldReturnFalseWhenNoStateParamPresent() {
        Map<String, String> queryParams = new HashMap<>();
        queryParams.put("code", EXAMPLE_AUTH_CODE);

        boolean result = authService.validateRequest(queryParams, SESSION_ID);

        assertThat(result, is(false));
        verify(redisConnectionService, never()).getValue(anyString());
    }

    @Test
    void shouldReturnFalseWhenInvalidStateParamPresent() {
        Map<String, String> queryParams = new HashMap<>();
        queryParams.put("state", new State().getValue());
        queryParams.put("code", EXAMPLE_AUTH_CODE);

        boolean result = authService.validateRequest(queryParams, SESSION_ID);

        assertThat(result, is(false));
        verify(redisConnectionService)
                .getValue(
                        AuthenticationAuthorizationService.AUTHENTICATION_STATE_STORAGE_PREFIX
                                + SESSION_ID);
    }

    @Test
    void shouldReturnFalseWhenNoCodeParamPresent() {
        Map<String, String> queryParams = new HashMap<>();
        queryParams.put("code", EXAMPLE_AUTH_CODE);

        boolean result = authService.validateRequest(queryParams, SESSION_ID);

        assertThat(result, is(false));
        verify(redisConnectionService, never()).getValue(anyString());
    }
}

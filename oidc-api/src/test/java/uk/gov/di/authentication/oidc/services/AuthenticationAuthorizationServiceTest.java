package uk.gov.di.authentication.oidc.services;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.OIDCError;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.oidc.exceptions.AuthenticationCallbackValidationException;
import uk.gov.di.orchestration.shared.entity.StateItem;
import uk.gov.di.orchestration.shared.services.StateStorageService;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static com.nimbusds.oauth2.sdk.OAuth2Error.ACCESS_DENIED_CODE;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.samePropertyValuesAs;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.oidc.services.AuthenticationAuthorizationService.AUTHENTICATION_STATE_STORAGE_PREFIX;

class AuthenticationAuthorizationServiceTest {
    private final StateStorageService stateStorageService = mock(StateStorageService.class);
    private AuthenticationAuthorizationService authService;
    private static final State STORED_STATE = new State();
    private static final String SESSION_ID = "a-session-id";
    private static final String EXAMPLE_AUTH_CODE = "any-text-will-do";

    @BeforeEach
    void setUp() {
        when(stateStorageService.getState(anyString()))
                .thenReturn(
                        Optional.of(
                                new StateItem(AUTHENTICATION_STATE_STORAGE_PREFIX + SESSION_ID)
                                        .withState(STORED_STATE.getValue())));
        authService = new AuthenticationAuthorizationService(stateStorageService);
    }

    @Test
    void shouldValidateRequestWithValidParams() {
        Map<String, String> queryParams = new HashMap<>();
        queryParams.put("state", STORED_STATE.getValue());
        queryParams.put("code", EXAMPLE_AUTH_CODE);

        assertDoesNotThrow(() -> authService.validateRequest(queryParams, SESSION_ID));
        verify(stateStorageService).getState(AUTHENTICATION_STATE_STORAGE_PREFIX + SESSION_ID);
    }

    @Test
    void shouldThrowWhenNoQueryParametersPresent() {
        Map<String, String> queryParams = new HashMap<>();

        var exception =
                assertThrows(
                        AuthenticationCallbackValidationException.class,
                        () -> authService.validateRequest(queryParams, SESSION_ID));
        assertThat(exception.getError(), is((equalTo(OAuth2Error.SERVER_ERROR))));
        assertThat(exception.getLogoutRequired(), is((equalTo(false))));
        verify(stateStorageService, never()).getState(anyString());
    }

    @Test
    void shouldThrowWhenErrorParamPresent() {
        Map<String, String> queryParams = new HashMap<>();
        queryParams.put("error", "some-error");

        var exception =
                assertThrows(
                        AuthenticationCallbackValidationException.class,
                        () -> authService.validateRequest(queryParams, SESSION_ID));
        assertThat(exception.getError(), is((equalTo(OAuth2Error.SERVER_ERROR))));
        assertThat(exception.getLogoutRequired(), is((equalTo(false))));
        verify(stateStorageService, never()).getState(anyString());
    }

    @ParameterizedTest
    @MethodSource("reauthErrorCases")
    void shouldThrowWhenErrorParamPresent(String reauthErrorCode, ErrorObject expectedErrorObject) {
        Map<String, String> queryParams = new HashMap<>();
        queryParams.put("error", reauthErrorCode);

        var exception =
                assertThrows(
                        AuthenticationCallbackValidationException.class,
                        () -> authService.validateRequest(queryParams, SESSION_ID));
        assertThat(exception.getError(), is((equalTo(expectedErrorObject))));
        assertThat(exception.getLogoutRequired(), is((equalTo(true))));
        verify(stateStorageService, never()).getState(anyString());
    }

    static Stream<Arguments> reauthErrorCases() {
        return Stream.of(
                Arguments.of(OAuth2Error.ACCESS_DENIED_CODE, OAuth2Error.ACCESS_DENIED),
                Arguments.of(OIDCError.LOGIN_REQUIRED_CODE, OIDCError.LOGIN_REQUIRED));
    }

    @Test
    void shouldThrowWhenNoStateParamPresent() {
        Map<String, String> queryParams = new HashMap<>();
        queryParams.put("code", EXAMPLE_AUTH_CODE);

        var exception =
                assertThrows(
                        AuthenticationCallbackValidationException.class,
                        () -> authService.validateRequest(queryParams, SESSION_ID));
        assertThat(exception.getError(), is((equalTo(OAuth2Error.SERVER_ERROR))));
        assertThat(exception.getLogoutRequired(), is((equalTo(false))));
        verify(stateStorageService, never()).getState(anyString());
    }

    @Test
    void shouldThrowWhenStateParamDoesNotMatchStoredState() {
        Map<String, String> queryParams = new HashMap<>();
        queryParams.put("state", new State().getValue());
        queryParams.put("code", EXAMPLE_AUTH_CODE);

        var exception =
                assertThrows(
                        AuthenticationCallbackValidationException.class,
                        () -> authService.validateRequest(queryParams, SESSION_ID));
        assertThat(
                exception.getError(),
                samePropertyValuesAs(
                        new ErrorObject(
                                ACCESS_DENIED_CODE,
                                "Access denied for security reasons, a new authentication request may be successful")));
        assertThat(exception.getLogoutRequired(), is((equalTo(false))));
        verify(stateStorageService).getState(AUTHENTICATION_STATE_STORAGE_PREFIX + SESSION_ID);
    }

    @Test
    void shouldThrowWhenNoStateFoundInDynamo() {
        when(stateStorageService.getState(AUTHENTICATION_STATE_STORAGE_PREFIX + SESSION_ID))
                .thenReturn(Optional.empty());
        Map<String, String> queryParams = new HashMap<>();
        queryParams.put("state", new State().getValue());
        queryParams.put("code", EXAMPLE_AUTH_CODE);

        var exception =
                assertThrows(
                        AuthenticationCallbackValidationException.class,
                        () -> authService.validateRequest(queryParams, SESSION_ID));
        assertThat(
                exception.getError(),
                samePropertyValuesAs(
                        new ErrorObject(
                                ACCESS_DENIED_CODE,
                                "Access denied for security reasons, a new authentication request may be successful")));
        assertThat(exception.getLogoutRequired(), is((equalTo(false))));
        verify(stateStorageService).getState(AUTHENTICATION_STATE_STORAGE_PREFIX + SESSION_ID);
    }

    @Test
    void shouldThrowWhenNoCodeParamPresent() {
        Map<String, String> queryParams = new HashMap<>();
        queryParams.put("state", STORED_STATE.getValue());

        var exception =
                assertThrows(
                        AuthenticationCallbackValidationException.class,
                        () -> authService.validateRequest(queryParams, SESSION_ID));
        assertThat(exception.getError(), is((equalTo(OAuth2Error.SERVER_ERROR))));
        assertThat(exception.getLogoutRequired(), is((equalTo(false))));
    }
}

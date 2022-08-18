package uk.gov.di.authentication.shared.validation;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.MFAMethod;
import uk.gov.di.authentication.shared.entity.MFAMethodType;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.sharedtest.helper.AuthAppStub;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_BLOCKED_KEY_PREFIX;

class AuthAppCodeValidatorTest {
    AuthAppCodeValidator authAppCodeValidator;
    Session mockSession;
    CodeStorageService mockCodeStorageService;
    ConfigurationService mockConfigurationService;
    DynamoService mockDynamoService;

    private final int MAX_RETRIES = 5;

    @BeforeEach
    void setUp() {
        this.mockSession = mock(Session.class);
        this.mockCodeStorageService = mock(CodeStorageService.class);
        this.mockConfigurationService = mock(ConfigurationService.class);
        this.mockDynamoService = mock(DynamoService.class);
    }

    @Test
    void returnsNoErrorOnValidAuthCode() {
        setUpValidAuthCode();
        var authAppStub = new AuthAppStub();
        String authCode =
                authAppStub.getAuthAppOneTimeCode(
                        "test-credential-value", NowHelper.now().getTime());

        assertEquals(Optional.empty(), authAppCodeValidator.validateCode(authCode));
    }

    @Test
    void returnsCorrectErrorWhenCodeBlockedForEmailAddress() {
        setUpBlockedUser();

        assertEquals(
                Optional.of(ErrorResponse.ERROR_1042),
                authAppCodeValidator.validateCode("any-code"));
    }

    @Test
    void returnsCorrectErrorWhenRetryLimitExceeded() {
        setUpRetryLimitExceededUser();

        assertEquals(
                Optional.of(ErrorResponse.ERROR_1042),
                authAppCodeValidator.validateCode("any-code"));
    }

    @Test
    void returnsCorrectErrorWhenNoAuthCodeIsFound() {
        setUpNoAuthCodeForUser();

        assertEquals(
                Optional.of(ErrorResponse.ERROR_1043),
                authAppCodeValidator.validateCode("any-code"));
    }

    @Test
    void returnsCorrectErrorWhenAuthCodeIsInvalid() {
        setUpValidAuthCode();

        assertEquals(
                Optional.of(ErrorResponse.ERROR_1043), authAppCodeValidator.validateCode("111111"));
        assertEquals(Optional.of(ErrorResponse.ERROR_1043), authAppCodeValidator.validateCode(""));
        assertEquals(
                Optional.of(ErrorResponse.ERROR_1043),
                authAppCodeValidator.validateCode("999999999999"));
    }

    private void setUpBlockedUser() {
        when(mockCodeStorageService.isBlockedForEmail(
                        "blocked-email-address", CODE_BLOCKED_KEY_PREFIX))
                .thenReturn(true);

        this.authAppCodeValidator =
                new AuthAppCodeValidator(
                        "blocked-email-address",
                        mockCodeStorageService,
                        mockConfigurationService,
                        mockDynamoService,
                        MAX_RETRIES);
    }

    private void setUpRetryLimitExceededUser() {
        when(mockCodeStorageService.isBlockedForEmail("email-address", CODE_BLOCKED_KEY_PREFIX))
                .thenReturn(false);
        when(mockCodeStorageService.getIncorrectMfaCodeAttemptsCount("email-address"))
                .thenReturn(MAX_RETRIES + 1);

        this.authAppCodeValidator =
                new AuthAppCodeValidator(
                        "email-address",
                        mockCodeStorageService,
                        mockConfigurationService,
                        mockDynamoService,
                        MAX_RETRIES);
    }

    private void setUpNoAuthCodeForUser() {
        when(mockCodeStorageService.isBlockedForEmail("email-address", CODE_BLOCKED_KEY_PREFIX))
                .thenReturn(false);
        when(mockDynamoService.getUserCredentialsFromEmail("email-address"))
                .thenReturn(mock(UserCredentials.class));

        this.authAppCodeValidator =
                new AuthAppCodeValidator(
                        "email-address",
                        mockCodeStorageService,
                        mockConfigurationService,
                        mockDynamoService,
                        MAX_RETRIES);
    }

    private void setUpValidAuthCode() {
        when(mockSession.getEmailAddress()).thenReturn("email-address");
        when(mockSession.getRetryCount()).thenReturn(0);
        when(mockCodeStorageService.isBlockedForEmail("email-address", CODE_BLOCKED_KEY_PREFIX))
                .thenReturn(false);
        when(mockConfigurationService.getAuthAppCodeAllowedWindows()).thenReturn(9);
        when(mockConfigurationService.getAuthAppCodeWindowLength()).thenReturn(30);

        UserCredentials mockUserCredentials = mock(UserCredentials.class);
        MFAMethod mockMfaMethod = mock(MFAMethod.class);
        when(mockMfaMethod.getMfaMethodType()).thenReturn(MFAMethodType.AUTH_APP.getValue());
        when(mockMfaMethod.getCredentialValue()).thenReturn("test-credential-value");
        when(mockMfaMethod.isEnabled()).thenReturn(true);
        List<MFAMethod> mockMfaMethodList = Collections.singletonList(mockMfaMethod);
        when(mockUserCredentials.getMfaMethods()).thenReturn(mockMfaMethodList);
        when(mockDynamoService.getUserCredentialsFromEmail("email-address"))
                .thenReturn(mockUserCredentials);

        this.authAppCodeValidator =
                new AuthAppCodeValidator(
                        "email-address",
                        mockCodeStorageService,
                        mockConfigurationService,
                        mockDynamoService,
                        MAX_RETRIES);
    }
}

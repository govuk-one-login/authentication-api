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
import uk.gov.di.authentication.shared.state.UserContext;
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
    UserContext mockUserContext;
    Session mockSession;
    CodeStorageService mockCodeStorageService;
    ConfigurationService mockConfigurationService;
    DynamoService mockDynamoService;

    int MAX_RETRIES = 5;

    @BeforeEach
    void setUp() {
        this.mockUserContext = mock(UserContext.class);
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

        assertEquals(Optional.empty(), authAppCodeValidator.codeValidationErrors(authCode));
    }

    @Test
    void returnsCorrectErrorWhenCodeBlockedForEmailAddress() {
        setUpBlockedUser();

        assertEquals(
                Optional.of(ErrorResponse.ERROR_1042),
                authAppCodeValidator.codeValidationErrors("any-code"));
    }

    @Test
    void returnsCorrectErrorWhenRetryLimitExceeded() {
        setUpRetryLimitExceededUser();

        assertEquals(
                Optional.of(ErrorResponse.ERROR_1042),
                authAppCodeValidator.codeValidationErrors("any-code"));
    }

    @Test
    void returnsCorrectErrorWhenNoAuthCodeIsFound() {
        setUpNoAuthCodeForUser();

        assertEquals(
                Optional.of(ErrorResponse.ERROR_1043),
                authAppCodeValidator.codeValidationErrors("any-code"));
    }

    @Test
    void returnsCorrectErrorWhenAuthCodeIsInvalid() {
        setUpInvalidAuthCode();

        assertEquals(
                Optional.of(ErrorResponse.ERROR_1043),
                authAppCodeValidator.codeValidationErrors("111111"));
    }

    private void setUpBlockedUser() {
        when(mockSession.getEmailAddress()).thenReturn("blocked-email-address");
        when(mockUserContext.getSession()).thenReturn(mockSession);
        when(mockCodeStorageService.isBlockedForEmail(
                        "blocked-email-address", CODE_BLOCKED_KEY_PREFIX))
                .thenReturn(true);

        this.authAppCodeValidator =
                new AuthAppCodeValidator(
                        MFAMethodType.AUTH_APP,
                        mockUserContext,
                        mockCodeStorageService,
                        mockConfigurationService,
                        mockDynamoService,
                        MAX_RETRIES);
    }

    private void setUpRetryLimitExceededUser() {
        when(mockSession.getEmailAddress()).thenReturn("email-address");
        when(mockSession.getRetryCount()).thenReturn(6);
        when(mockUserContext.getSession()).thenReturn(mockSession);
        when(mockCodeStorageService.isBlockedForEmail("email-address", CODE_BLOCKED_KEY_PREFIX))
                .thenReturn(false);

        this.authAppCodeValidator =
                new AuthAppCodeValidator(
                        MFAMethodType.AUTH_APP,
                        mockUserContext,
                        mockCodeStorageService,
                        mockConfigurationService,
                        mockDynamoService,
                        MAX_RETRIES);
    }

    private void setUpNoAuthCodeForUser() {
        when(mockSession.getEmailAddress()).thenReturn("email-address");
        when(mockSession.getRetryCount()).thenReturn(0);
        when(mockUserContext.getSession()).thenReturn(mockSession);
        when(mockCodeStorageService.isBlockedForEmail("email-address", CODE_BLOCKED_KEY_PREFIX))
                .thenReturn(false);
        //when(mockConfigurationService.getMaxPasswordRetries()).thenReturn(5);
        when(mockDynamoService.getUserCredentialsFromEmail("email-address"))
                .thenReturn(mock(UserCredentials.class));

        this.authAppCodeValidator =
                new AuthAppCodeValidator(
                        MFAMethodType.AUTH_APP,
                        mockUserContext,
                        mockCodeStorageService,
                        mockConfigurationService,
                        mockDynamoService,
                        MAX_RETRIES);
    }

    private void setUpInvalidAuthCode() {
        when(mockSession.getEmailAddress()).thenReturn("email-address");
        when(mockSession.getRetryCount()).thenReturn(0);
        when(mockUserContext.getSession()).thenReturn(mockSession);
        when(mockCodeStorageService.isBlockedForEmail("email-address", CODE_BLOCKED_KEY_PREFIX))
                .thenReturn(false);

        UserCredentials mockUserCredentials = mock(UserCredentials.class);
        MFAMethod mockMfaMethod = mock(MFAMethod.class);
        when(mockMfaMethod.getMfaMethodType()).thenReturn(MFAMethodType.AUTH_APP.getValue());
        when(mockMfaMethod.getCredentialValue()).thenReturn("test-credential-value");
        List<MFAMethod> mockMfaMethodList = Collections.singletonList(mockMfaMethod);
        when(mockUserCredentials.getMfaMethods()).thenReturn(mockMfaMethodList);
        when(mockDynamoService.getUserCredentialsFromEmail("email-address"))
                .thenReturn(mockUserCredentials);

        this.authAppCodeValidator =
                new AuthAppCodeValidator(
                        MFAMethodType.AUTH_APP,
                        mockUserContext,
                        mockCodeStorageService,
                        mockConfigurationService,
                        mockDynamoService,
                        MAX_RETRIES);
    }

    private void setUpValidAuthCode() {
        when(mockSession.getEmailAddress()).thenReturn("email-address");
        when(mockSession.getRetryCount()).thenReturn(0);
        when(mockUserContext.getSession()).thenReturn(mockSession);
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
                        MFAMethodType.AUTH_APP,
                        mockUserContext,
                        mockCodeStorageService,
                        mockConfigurationService,
                        mockDynamoService,
                        MAX_RETRIES);
    }
}

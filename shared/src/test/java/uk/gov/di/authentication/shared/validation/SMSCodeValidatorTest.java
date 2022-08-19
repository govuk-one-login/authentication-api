package uk.gov.di.authentication.shared.validation;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_BLOCKED_KEY_PREFIX;

public class SMSCodeValidatorTest {
    SMSCodeValidator smsCodeValidator;
    UserContext mockUserContext;
    Session mockSession;
    CodeStorageService mockCodeStorageService;
    ConfigurationService mockConfigurationService;
    DynamoService mockDynamoService;

    private final int MAX_RETRIES = 5;
    private final String EMAIL_ADDRESS = "email-address";

    @BeforeEach
    void setUp() {
        this.mockUserContext = mock(UserContext.class);
        this.mockSession = mock(Session.class);
        this.mockCodeStorageService = mock(CodeStorageService.class);
        this.mockConfigurationService = mock(ConfigurationService.class);
        this.mockDynamoService = mock(DynamoService.class);
    }

    @Test
    void returnsCorrectErrorWhenCodeBlockedForEmailAddress() {
        setUpBlockedUser();

        assertEquals(
                Optional.of(ErrorResponse.ERROR_1027), smsCodeValidator.validateCode("any-code"));
    }

    @Test
    void returnsCorrectErrorWhenRetryLimitExceeded() {
        setUpRetryLimitExceededUser();

        assertEquals(
                Optional.of(ErrorResponse.ERROR_1027), smsCodeValidator.validateCode("any-code"));
    }

    @Test
    void returnsCorrectErrorWhenOtpIsInvalid() {
        setUpInvalidOtp();

        assertEquals(
                Optional.of(ErrorResponse.ERROR_1035), smsCodeValidator.validateCode("any-code"));
    }

    private void setUpBlockedUser() {
        String BLOCKED_EMAIL_ADDRESS = "blocked-email-address";
        when(mockSession.getEmailAddress()).thenReturn(BLOCKED_EMAIL_ADDRESS);
        when(mockUserContext.getSession()).thenReturn(mockSession);
        when(mockCodeStorageService.isBlockedForEmail(
                        BLOCKED_EMAIL_ADDRESS, CODE_BLOCKED_KEY_PREFIX))
                .thenReturn(true);

        this.smsCodeValidator =
                new SMSCodeValidator(
                        BLOCKED_EMAIL_ADDRESS,
                        mockCodeStorageService,
                        mockDynamoService,
                        MAX_RETRIES);
    }

    private void setUpRetryLimitExceededUser() {
        when(mockSession.getEmailAddress()).thenReturn(EMAIL_ADDRESS);
        when(mockUserContext.getSession()).thenReturn(mockSession);
        when(mockCodeStorageService.isBlockedForEmail(EMAIL_ADDRESS, CODE_BLOCKED_KEY_PREFIX))
                .thenReturn(false);
        when(mockCodeStorageService.getIncorrectMfaCodeAttemptsCount(EMAIL_ADDRESS))
                .thenReturn(MAX_RETRIES + 1);

        this.smsCodeValidator =
                new SMSCodeValidator(
                        EMAIL_ADDRESS, mockCodeStorageService, mockDynamoService, MAX_RETRIES);
    }

    private void setUpInvalidOtp() {
        when(mockSession.getEmailAddress()).thenReturn(EMAIL_ADDRESS);
        when(mockUserContext.getSession()).thenReturn(mockSession);
        when(mockCodeStorageService.isValidOtpCode(
                        EMAIL_ADDRESS,
                        CODE_BLOCKED_KEY_PREFIX,
                        NotificationType.VERIFY_PHONE_NUMBER))
                .thenReturn(false);

        this.smsCodeValidator =
                new SMSCodeValidator(
                        EMAIL_ADDRESS, mockCodeStorageService, mockDynamoService, MAX_RETRIES);
    }
}

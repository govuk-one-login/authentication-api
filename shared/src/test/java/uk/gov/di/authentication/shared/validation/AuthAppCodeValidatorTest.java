package uk.gov.di.authentication.shared.validation;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.entity.VerifyMfaCodeRequest;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
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
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
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

    private static final String AUTH_APP_SECRET =
            "JZ5PYIOWNZDAOBA65S5T77FEEKYCCIT2VE4RQDAJD7SO73T3LODA";
    private final int MAX_RETRIES = 5;

    @BeforeEach
    void setUp() {
        this.mockSession = mock(Session.class);
        this.mockCodeStorageService = mock(CodeStorageService.class);
        this.mockConfigurationService = mock(ConfigurationService.class);
        this.mockDynamoService = mock(DynamoService.class);
    }

    private static Stream<Arguments> validatorParams() {
        return Stream.of(
                Arguments.of(JourneyType.SIGN_IN, null),
                Arguments.of(JourneyType.REGISTRATION, AUTH_APP_SECRET));
    }

    @ParameterizedTest
    @MethodSource("validatorParams")
    void returnsNoErrorOnValidAuthCode(JourneyType journeyType, String authAppSecret) {
        setUpValidAuthCode(journeyType);
        var authAppStub = new AuthAppStub();
        String authCode =
                authAppStub.getAuthAppOneTimeCode(AUTH_APP_SECRET, NowHelper.now().getTime());

        assertEquals(
                Optional.empty(),
                authAppCodeValidator.validateCode(
                        new VerifyMfaCodeRequest(
                                MFAMethodType.AUTH_APP, authCode, journeyType, authAppSecret)));
    }

    @ParameterizedTest
    @MethodSource("validatorParams")
    void returnsCorrectErrorWhenCodeBlockedForEmailAddress(
            JourneyType journeyType, String authAppSecret) {
        setUpBlockedUser(journeyType);

        assertEquals(
                Optional.of(ErrorResponse.ERROR_1042),
                authAppCodeValidator.validateCode(
                        new VerifyMfaCodeRequest(
                                MFAMethodType.AUTH_APP, "000000", journeyType, authAppSecret)));
    }

    @ParameterizedTest
    @MethodSource("validatorParams")
    void returnsCorrectErrorWhenRetryLimitExceeded(JourneyType journeyType, String authAppSecret) {
        setUpRetryLimitExceededUser(journeyType);

        assertEquals(
                Optional.of(ErrorResponse.ERROR_1042),
                authAppCodeValidator.validateCode(
                        new VerifyMfaCodeRequest(
                                MFAMethodType.AUTH_APP, "000000", journeyType, authAppSecret)));
    }

    @ParameterizedTest
    @MethodSource("validatorParams")
    void returnsCorrectErrorWhenNoAuthCodeIsFound(JourneyType journeyType) {
        setUpNoAuthCodeForUser(journeyType);

        assertEquals(
                Optional.of(ErrorResponse.ERROR_1043),
                authAppCodeValidator.validateCode(
                        new VerifyMfaCodeRequest(MFAMethodType.AUTH_APP, "000000", journeyType)));
    }

    @Test
    void shouldReturnErrorWhenAuthAppSecretIsInvalid() {
        setUpValidAuthCode(JourneyType.REGISTRATION);

        assertThat(
                authAppCodeValidator.validateCode(
                        new VerifyMfaCodeRequest(
                                MFAMethodType.AUTH_APP,
                                "000000",
                                JourneyType.REGISTRATION,
                                "not-base-32-encoded-secret")),
                equalTo(Optional.of(ErrorResponse.ERROR_1041)));
    }

    @ParameterizedTest
    @MethodSource("validatorParams")
    void returnsCorrectErrorWhenAuthCodeIsInvalid(JourneyType journeyType, String authAppSecret) {
        setUpValidAuthCode(journeyType);

        assertEquals(
                Optional.of(ErrorResponse.ERROR_1043),
                authAppCodeValidator.validateCode(
                        new VerifyMfaCodeRequest(
                                MFAMethodType.AUTH_APP,
                                "111111",
                                JourneyType.REGISTRATION,
                                authAppSecret)));
        assertEquals(
                Optional.of(ErrorResponse.ERROR_1043),
                authAppCodeValidator.validateCode(
                        new VerifyMfaCodeRequest(
                                MFAMethodType.AUTH_APP,
                                "",
                                JourneyType.REGISTRATION,
                                authAppSecret)));
        assertEquals(
                Optional.of(ErrorResponse.ERROR_1043),
                authAppCodeValidator.validateCode(
                        new VerifyMfaCodeRequest(
                                MFAMethodType.AUTH_APP,
                                "999999999999",
                                JourneyType.REGISTRATION,
                                authAppSecret)));
    }

    private void setUpBlockedUser(JourneyType journeyType) {
        when(mockCodeStorageService.isBlockedForEmail(
                        "blocked-email-address", CODE_BLOCKED_KEY_PREFIX))
                .thenReturn(true);

        this.authAppCodeValidator =
                new AuthAppCodeValidator(
                        "blocked-email-address",
                        mockCodeStorageService,
                        mockConfigurationService,
                        mockDynamoService,
                        MAX_RETRIES,
                        journeyType);
    }

    private void setUpRetryLimitExceededUser(JourneyType journeyType) {
        when(mockCodeStorageService.isBlockedForEmail("email-address", CODE_BLOCKED_KEY_PREFIX))
                .thenReturn(false);
        when(mockCodeStorageService.getIncorrectMfaCodeAttemptsCount(
                        "email-address", MFAMethodType.AUTH_APP))
                .thenReturn(MAX_RETRIES + 1);

        this.authAppCodeValidator =
                new AuthAppCodeValidator(
                        "email-address",
                        mockCodeStorageService,
                        mockConfigurationService,
                        mockDynamoService,
                        MAX_RETRIES,
                        journeyType);
    }

    private void setUpNoAuthCodeForUser(JourneyType journeyType) {
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
                        MAX_RETRIES,
                        journeyType);
    }

    private void setUpValidAuthCode(JourneyType journeyType) {
        when(mockSession.getEmailAddress()).thenReturn("email-address");
        when(mockSession.getRetryCount()).thenReturn(0);
        when(mockCodeStorageService.isBlockedForEmail("email-address", CODE_BLOCKED_KEY_PREFIX))
                .thenReturn(false);
        when(mockConfigurationService.getAuthAppCodeAllowedWindows()).thenReturn(9);
        when(mockConfigurationService.getAuthAppCodeWindowLength()).thenReturn(30);

        UserCredentials mockUserCredentials = mock(UserCredentials.class);
        MFAMethod mockMfaMethod = mock(MFAMethod.class);
        when(mockMfaMethod.getMfaMethodType()).thenReturn(MFAMethodType.AUTH_APP.getValue());
        when(mockMfaMethod.getCredentialValue()).thenReturn(AUTH_APP_SECRET);
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
                        MAX_RETRIES,
                        journeyType);
    }
}

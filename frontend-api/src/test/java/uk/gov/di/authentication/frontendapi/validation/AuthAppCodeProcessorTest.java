package uk.gov.di.authentication.frontendapi.validation;

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
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.state.UserContext;
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

class AuthAppCodeProcessorTest {
    AuthAppCodeProcessor authAppCodeProcessor;
    Session mockSession;
    CodeStorageService mockCodeStorageService;
    ConfigurationService mockConfigurationService;
    DynamoService mockDynamoService;
    AuditService mockAuditService;
    UserContext mockUserContext;

    private static final String AUTH_APP_SECRET =
            "JZ5PYIOWNZDAOBA65S5T77FEEKYCCIT2VE4RQDAJD7SO73T3LODA";
    private final int MAX_RETRIES = 5;

    @BeforeEach
    void setUp() {
        this.mockSession = mock(Session.class);
        this.mockCodeStorageService = mock(CodeStorageService.class);
        this.mockConfigurationService = mock(ConfigurationService.class);
        this.mockDynamoService = mock(DynamoService.class);
        this.mockAuditService = mock(AuditService.class);
        this.mockUserContext = mock(UserContext.class);
        when(mockUserContext.getSession()).thenReturn(mock(Session.class));
    }

    private static Stream<Arguments> validatorParams() {
        return Stream.of(Arguments.of(false, null), Arguments.of(true, AUTH_APP_SECRET));
    }

    @ParameterizedTest
    @MethodSource("validatorParams")
    void returnsNoErrorOnValidAuthCode(boolean isRegistration, String authAppSecret) {
        setUpValidAuthCode(isRegistration);
        var authAppStub = new AuthAppStub();
        String authCode =
                authAppStub.getAuthAppOneTimeCode(AUTH_APP_SECRET, NowHelper.now().getTime());

        assertEquals(
                Optional.empty(),
                authAppCodeProcessor.validateCode(
                        new VerifyMfaCodeRequest(
                                MFAMethodType.AUTH_APP,
                                authCode,
                                isRegistration,
                                JourneyType.REGISTRATION,
                                authAppSecret)));
    }

    @ParameterizedTest
    @MethodSource("validatorParams")
    void returnsCorrectErrorWhenCodeBlockedForEmailAddress(
            boolean isRegistration, String authAppSecret) {
        setUpBlockedUser(isRegistration);

        assertEquals(
                Optional.of(ErrorResponse.ERROR_1042),
                authAppCodeProcessor.validateCode(
                        new VerifyMfaCodeRequest(
                                MFAMethodType.AUTH_APP,
                                "000000",
                                isRegistration,
                                JourneyType.REGISTRATION,
                                authAppSecret)));
    }

    @ParameterizedTest
    @MethodSource("validatorParams")
    void returnsCorrectErrorWhenRetryLimitExceeded(boolean isRegistration, String authAppSecret) {
        setUpRetryLimitExceededUser(isRegistration);

        assertEquals(
                Optional.of(ErrorResponse.ERROR_1042),
                authAppCodeProcessor.validateCode(
                        new VerifyMfaCodeRequest(
                                MFAMethodType.AUTH_APP,
                                "000000",
                                isRegistration,
                                JourneyType.REGISTRATION,
                                authAppSecret)));
    }

    @ParameterizedTest
    @MethodSource("validatorParams")
    void returnsCorrectErrorWhenNoAuthCodeIsFound(boolean isRegistration) {
        setUpNoAuthCodeForUser(isRegistration);

        assertEquals(
                Optional.of(ErrorResponse.ERROR_1043),
                authAppCodeProcessor.validateCode(
                        new VerifyMfaCodeRequest(
                                MFAMethodType.AUTH_APP,
                                "000000",
                                isRegistration,
                                JourneyType.REGISTRATION)));
    }

    @Test
    void shouldReturnErrorWhenAuthAppSecretIsInvalid() {
        setUpValidAuthCode(true);

        assertThat(
                authAppCodeProcessor.validateCode(
                        new VerifyMfaCodeRequest(
                                MFAMethodType.AUTH_APP,
                                "000000",
                                true,
                                JourneyType.REGISTRATION,
                                "not-base-32-encoded-secret")),
                equalTo(Optional.of(ErrorResponse.ERROR_1041)));
    }

    @ParameterizedTest
    @MethodSource("validatorParams")
    void returnsCorrectErrorWhenAuthCodeIsInvalid(boolean isRegistration, String authAppSecret) {
        setUpValidAuthCode(isRegistration);

        assertEquals(
                Optional.of(ErrorResponse.ERROR_1043),
                authAppCodeProcessor.validateCode(
                        new VerifyMfaCodeRequest(
                                MFAMethodType.AUTH_APP,
                                "111111",
                                true,
                                JourneyType.REGISTRATION,
                                authAppSecret)));
        assertEquals(
                Optional.of(ErrorResponse.ERROR_1043),
                authAppCodeProcessor.validateCode(
                        new VerifyMfaCodeRequest(
                                MFAMethodType.AUTH_APP,
                                "",
                                true,
                                JourneyType.REGISTRATION,
                                authAppSecret)));
        assertEquals(
                Optional.of(ErrorResponse.ERROR_1043),
                authAppCodeProcessor.validateCode(
                        new VerifyMfaCodeRequest(
                                MFAMethodType.AUTH_APP,
                                "999999999999",
                                true,
                                JourneyType.REGISTRATION,
                                authAppSecret)));
    }

    private void setUpBlockedUser(boolean isRegistration) {
        when(mockUserContext.getSession().getEmailAddress()).thenReturn("blocked-email-address");
        when(mockCodeStorageService.isBlockedForEmail(
                        "blocked-email-address", CODE_BLOCKED_KEY_PREFIX))
                .thenReturn(true);

        var journeyType = isRegistration ? JourneyType.REGISTRATION : JourneyType.SIGN_IN;

        this.authAppCodeProcessor =
                new AuthAppCodeProcessor(
                        mockUserContext,
                        mockCodeStorageService,
                        mockConfigurationService,
                        mockDynamoService,
                        MAX_RETRIES,
                        journeyType,
                        mockAuditService);
    }

    private void setUpRetryLimitExceededUser(boolean isRegistration) {
        when(mockUserContext.getSession().getEmailAddress()).thenReturn("email-address");
        when(mockCodeStorageService.isBlockedForEmail("email-address", CODE_BLOCKED_KEY_PREFIX))
                .thenReturn(false);
        when(mockCodeStorageService.getIncorrectMfaCodeAttemptsCount(
                        "email-address", MFAMethodType.AUTH_APP))
                .thenReturn(MAX_RETRIES + 1);

        var journeyType = isRegistration ? JourneyType.REGISTRATION : JourneyType.SIGN_IN;

        this.authAppCodeProcessor =
                new AuthAppCodeProcessor(
                        mockUserContext,
                        mockCodeStorageService,
                        mockConfigurationService,
                        mockDynamoService,
                        MAX_RETRIES,
                        journeyType,
                        mockAuditService);
    }

    private void setUpNoAuthCodeForUser(boolean isRegistration) {
        when(mockUserContext.getSession().getEmailAddress()).thenReturn("email-address");
        var journeyType = isRegistration ? JourneyType.REGISTRATION : JourneyType.SIGN_IN;

        when(mockCodeStorageService.isBlockedForEmail("email-address", CODE_BLOCKED_KEY_PREFIX))
                .thenReturn(false);
        when(mockDynamoService.getUserCredentialsFromEmail("email-address"))
                .thenReturn(mock(UserCredentials.class));

        this.authAppCodeProcessor =
                new AuthAppCodeProcessor(
                        mockUserContext,
                        mockCodeStorageService,
                        mockConfigurationService,
                        mockDynamoService,
                        MAX_RETRIES,
                        journeyType,
                        mockAuditService);
    }

    private void setUpValidAuthCode(boolean isRegistration) {
        when(mockUserContext.getSession().getEmailAddress()).thenReturn("email-address");
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

        var journeyType = isRegistration ? JourneyType.REGISTRATION : JourneyType.SIGN_IN;

        this.authAppCodeProcessor =
                new AuthAppCodeProcessor(
                        mockUserContext,
                        mockCodeStorageService,
                        mockConfigurationService,
                        mockDynamoService,
                        MAX_RETRIES,
                        journeyType,
                        mockAuditService);
    }
}

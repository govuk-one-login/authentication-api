package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.google.gson.JsonParser;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.CheckUserExistsResponse;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.entity.TermsAndConditions;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.CommonTestVariables;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;
import uk.gov.di.authentication.userpermissions.PermissionDecisionManager;
import uk.gov.di.authentication.userpermissions.entity.DecisionError;
import uk.gov.di.authentication.userpermissions.entity.LockoutInformation;
import uk.gov.di.authentication.userpermissions.entity.PermittedData;
import uk.gov.di.authentication.userpermissions.entity.TemporarilyLockedOutData;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Stream;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_ACCOUNT_TEMPORARILY_LOCKED;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.CLIENT_SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.DI_PERSISTENT_SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.ENCODED_DEVICE_DETAILS;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.IP_ADDRESS;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.VALID_HEADERS;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.VALID_HEADERS_WITHOUT_AUDIT_ENCODED;
import static uk.gov.di.authentication.sharedtest.helper.RequestEventHelper.contextWithSourceIp;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class CheckUserExistsHandlerTest {

    private final Context context = mock(Context.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final AuthSessionService authSessionService = mock(AuthSessionService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final CodeStorageService codeStorageService = mock(CodeStorageService.class);
    private final PermissionDecisionManager permissionDecisionManager =
            mock(PermissionDecisionManager.class);
    private CheckUserExistsHandler handler;
    private static final Json objectMapper = SerializationService.getInstance();
    private static final String CLIENT_ID = "test-client-id";
    private static final String SECTOR_HOST = "sector-identifier";
    private final AuthSessionItem authSession =
            new AuthSessionItem()
                    .withSessionId(SESSION_ID)
                    .withRequestedCredentialStrength(CredentialTrustLevel.MEDIUM_LEVEL)
                    .withClientId(CLIENT_ID)
                    .withRpSectorIdentifierHost(SECTOR_HOST);
    private static final Subject SUBJECT = new Subject();
    private static final String EMAIL_ADDRESS = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final ByteBuffer SALT =
            ByteBuffer.wrap("a-test-salt".getBytes(StandardCharsets.UTF_8));

    private static final AuditContext AUDIT_CONTEXT =
            new AuditContext(
                    CLIENT_ID,
                    CLIENT_SESSION_ID,
                    SESSION_ID,
                    AuditService.UNKNOWN,
                    EMAIL_ADDRESS,
                    IP_ADDRESS,
                    AuditService.UNKNOWN,
                    DI_PERSISTENT_SESSION_ID,
                    Optional.of(ENCODED_DEVICE_DETAILS),
                    new ArrayList<>());

    @RegisterExtension
    public final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(CheckUserExistsHandler.class);

    @AfterEach
    void tearDown() {
        assertThat(logging.events(), not(hasItem(withMessageContaining(SESSION_ID))));
    }

    @BeforeEach
    void setup() {
        when(context.getAwsRequestId()).thenReturn("aws-session-id");
        when(configurationService.getMaxPasswordRetries()).thenReturn(5);
        when(codeStorageService.isBlockedForEmail(any(), any())).thenReturn(false);
        when(configurationService.getInternalSectorUri()).thenReturn("https://test.account.gov.uk");

        handler =
                new CheckUserExistsHandler(
                        configurationService,
                        authSessionService,
                        authenticationService,
                        auditService,
                        permissionDecisionManager);
        reset(authenticationService);
        reset(permissionDecisionManager);

        // Setup default PermissionDecisionManager behavior after reset
        when(permissionDecisionManager.canReceivePassword(any(), any(), any(), any(), any()))
                .thenAnswer(
                        inv ->
                                Result.success(
                                        inv.getArgument(2, Function.class)
                                                .apply(new PermittedData(0))));
        when(permissionDecisionManager.canVerifyMfaOtp(any(), any(), any(), any()))
                .thenAnswer(
                        inv ->
                                Result.success(
                                        inv.getArgument(2, Function.class)
                                                .apply(new PermittedData(0))));
    }

    @Nested
    class WhenUserExists {
        @BeforeEach
        void setup() {
            authSessionExists();
            var userProfile =
                    generateUserProfile().withPhoneNumber(CommonTestVariables.UK_MOBILE_NUMBER);
            setupUserProfileAndClient(Optional.of(userProfile));
        }

        @Test
        void shouldReturn200WithRelevantMfaMethod() {
            MFAMethod mfaMethod1 = verifiedMfaMethod(MFAMethodType.AUTH_APP, false);
            MFAMethod mfaMethod2 = verifiedMfaMethod(MFAMethodType.SMS, true);
            when(authenticationService.getUserCredentialsFromEmail(EMAIL_ADDRESS))
                    .thenReturn(
                            new UserCredentials().withMfaMethods(List.of(mfaMethod1, mfaMethod2)));

            var result = handler.handleRequest(userExistsRequest(EMAIL_ADDRESS), context);
            var phoneNumber = CommonTestVariables.UK_MOBILE_NUMBER;

            assertThat(result, hasStatus(200));
            var expectedResponse =
                    format(
                            """
                    {"email":%s,
                    "doesUserExist":true,
                    "mfaMethodType":"SMS",
                    "phoneNumberLastThree":"%s",
                    "lockoutInformation":[],
                    "hasActivePasskey":false}
                    """,
                            EMAIL_ADDRESS, phoneNumber.substring(phoneNumber.length() - 3));
            assertEquals(
                    JsonParser.parseString(result.getBody()),
                    JsonParser.parseString(expectedResponse));
            verify(authSessionService).updateSession(any(AuthSessionItem.class));
            assertEquals(getExpectedInternalPairwiseId(), authSession.getInternalCommonSubjectId());
        }

        private static Stream<Arguments> mfaMethodsToExpectedResponseFields() {
            var phoneNumber = CommonTestVariables.UK_MOBILE_NUMBER;
            var defaultSmsMethod =
                    MFAMethod.smsMfaMethod(
                            true, true, phoneNumber, PriorityIdentifier.DEFAULT, "some-identifier");
            var defaultAuthAppMethod =
                    MFAMethod.authAppMfaMethod(
                            "some-credential",
                            true,
                            true,
                            PriorityIdentifier.DEFAULT,
                            "auth-app-mfa-id");
            return Stream.of(
                    Arguments.of(
                            defaultSmsMethod,
                            MFAMethodType.SMS,
                            phoneNumber.substring(phoneNumber.length() - 3)),
                    Arguments.of(defaultAuthAppMethod, MFAMethodType.AUTH_APP, null));
        }

        @ParameterizedTest
        @MethodSource("mfaMethodsToExpectedResponseFields")
        void shouldReturn200WithRelevantMfaMethodForMigratedUser(
                MFAMethod mfaMethod,
                MFAMethodType expectedMfaMethodType,
                String expectedPhoneNumberLastThree) {
            var userProfile = generateUserProfile().withMfaMethodsMigrated(true);
            setupUserProfileAndClient(Optional.of(userProfile));
            when(authenticationService.getUserCredentialsFromEmail(EMAIL_ADDRESS))
                    .thenReturn(new UserCredentials().withMfaMethods(List.of(mfaMethod)));

            var result = handler.handleRequest(userExistsRequest(EMAIL_ADDRESS), context);

            assertThat(result, hasStatus(200));
            var expectedFormattedAndRedactedPhoneNumber =
                    expectedPhoneNumberLastThree == null
                            ? "null"
                            : format("\"%s\"", expectedPhoneNumberLastThree);
            var expectedResponse =
                    format(
                            """
                    {"email":%s,
                    "doesUserExist":true,
                    "mfaMethodType":"%s",
                    "phoneNumberLastThree": %s,
                    "lockoutInformation":[],
                    "hasActivePasskey":false}
                    """,
                            EMAIL_ADDRESS,
                            expectedMfaMethodType,
                            expectedFormattedAndRedactedPhoneNumber);
            assertEquals(
                    JsonParser.parseString(expectedResponse),
                    JsonParser.parseString(result.getBody()));
            verify(authSessionService).updateSession(any(AuthSessionItem.class));
            assertEquals(getExpectedInternalPairwiseId(), authSession.getInternalCommonSubjectId());
        }

        @Test
        void shouldSubmitTheRelevantAuditEvent() {
            when(authenticationService.getUserCredentialsFromEmail(EMAIL_ADDRESS))
                    .thenReturn(new UserCredentials().withMfaMethods(List.of()));
            var result = handler.handleRequest(userExistsRequest(EMAIL_ADDRESS), context);

            assertThat(result, hasStatus(200));
            verify(auditService)
                    .submitAuditEvent(
                            FrontendAuditableEvent.AUTH_CHECK_USER_KNOWN_EMAIL,
                            AUDIT_CONTEXT.withSubjectId(getExpectedInternalPairwiseId()),
                            AuditService.MetadataPair.pair(
                                    "rpPairwiseId", getExpectedRpPairwiseId()));
        }

        @Test
        void checkAuditEventStillEmittedWhenTICFHeaderNotProvided() {
            when(authenticationService.getUserCredentialsFromEmail(EMAIL_ADDRESS))
                    .thenReturn(new UserCredentials().withMfaMethods(List.of()));
            var req = userExistsRequest(EMAIL_ADDRESS);
            req.setHeaders(VALID_HEADERS_WITHOUT_AUDIT_ENCODED);

            var result = handler.handleRequest(req, context);

            assertThat(result, hasStatus(200));
            verify(auditService)
                    .submitAuditEvent(
                            FrontendAuditableEvent.AUTH_CHECK_USER_KNOWN_EMAIL,
                            AUDIT_CONTEXT
                                    .withSubjectId(getExpectedInternalPairwiseId())
                                    .withTxmaAuditEncoded(Optional.empty()),
                            AuditService.MetadataPair.pair(
                                    "rpPairwiseId", getExpectedRpPairwiseId()));
        }

        @Test
        void shouldReturn200WithLockInformationIfUserExistsAndMfaIsAuthApp() {
            var lockoutExpiry = java.time.Instant.now().plusSeconds(15);
            var signInLockout =
                    new TemporarilyLockedOutData(
                            uk.gov.di.authentication.userpermissions.entity.ForbiddenReason
                                    .EXCEEDED_INCORRECT_PASSWORD_SUBMISSION_LIMIT,
                            5,
                            lockoutExpiry,
                            false);
            var passwordResetLockout =
                    new TemporarilyLockedOutData(
                            uk.gov.di.authentication.userpermissions.entity.ForbiddenReason
                                    .EXCEEDED_INCORRECT_PASSWORD_SUBMISSION_LIMIT,
                            5,
                            lockoutExpiry,
                            false);

            when(permissionDecisionManager.canVerifyMfaOtp(
                            eq(JourneyType.SIGN_IN), any(), any(), any()))
                    .thenAnswer(
                            inv ->
                                    Result.success(
                                            inv.getArgument(2, Function.class)
                                                    .apply(signInLockout)));
            when(permissionDecisionManager.canVerifyMfaOtp(
                            eq(JourneyType.PASSWORD_RESET_MFA), any(), any(), any()))
                    .thenAnswer(
                            inv ->
                                    Result.success(
                                            inv.getArgument(2, Function.class)
                                                    .apply(passwordResetLockout)));

            MFAMethod mfaMethod1 = verifiedMfaMethod(MFAMethodType.AUTH_APP, true);
            when(authenticationService.getUserCredentialsFromEmail(EMAIL_ADDRESS))
                    .thenReturn(new UserCredentials().withMfaMethods(List.of(mfaMethod1)));
            var event = userExistsRequest(EMAIL_ADDRESS);

            var result = handler.handleRequest(event, context);
            verify(authSessionService).updateSession(any(AuthSessionItem.class));
            assertThat(result, hasStatus(200));

            var expectedResponse =
                    new CheckUserExistsResponse(
                            EMAIL_ADDRESS,
                            true,
                            MFAMethodType.AUTH_APP,
                            null,
                            List.of(
                                    new LockoutInformation(
                                            "codeBlock",
                                            MFAMethodType.AUTH_APP,
                                            lockoutExpiry.getEpochSecond(),
                                            JourneyType.SIGN_IN),
                                    new LockoutInformation(
                                            "codeBlock",
                                            MFAMethodType.AUTH_APP,
                                            lockoutExpiry.getEpochSecond(),
                                            JourneyType.PASSWORD_RESET_MFA)),
                            false);
            assertThat(result, hasJsonBody(expectedResponse));
        }

        @Test
        void shouldReturnNoRedactedPhoneNumberIfNotPresent() throws Json.JsonException {
            setupUserProfileAndClient(Optional.of(generateUserProfile()));

            MFAMethod mfaMethod = verifiedMfaMethod(MFAMethodType.SMS, true);
            when(authenticationService.getUserCredentialsFromEmail(EMAIL_ADDRESS))
                    .thenReturn(new UserCredentials().withMfaMethods(List.of(mfaMethod)));

            var result = handler.handleRequest(userExistsRequest(EMAIL_ADDRESS), context);

            assertThat(result, hasStatus(200));
            var checkUserExistsResponse =
                    objectMapper.readValue(result.getBody(), CheckUserExistsResponse.class);
            assertEquals(EMAIL_ADDRESS, checkUserExistsResponse.email());
            assertNull(checkUserExistsResponse.phoneNumberLastThree());
        }

        @Test
        void shouldReturn400AndSaveEmailInUserSessionIfUserAccountIsLocked() {
            var lockedOutDecision =
                    new TemporarilyLockedOutData(
                            uk.gov.di.authentication.userpermissions.entity.ForbiddenReason
                                    .EXCEEDED_INCORRECT_PASSWORD_SUBMISSION_LIMIT,
                            5,
                            java.time.Instant.now().plusSeconds(3600),
                            false);
            when(permissionDecisionManager.canReceivePassword(any(), any(), any(), any(), any()))
                    .thenAnswer(
                            inv ->
                                    Result.success(
                                            inv.getArgument(2, Function.class)
                                                    .apply(lockedOutDecision)));

            var result = handler.handleRequest(userExistsRequest(EMAIL_ADDRESS), context);

            assertThat(result, hasStatus(400));
            assertThat(result, hasJsonBody(ErrorResponse.ACCT_TEMPORARILY_LOCKED));
            verify(authSessionService, times(1)).updateSession(any(AuthSessionItem.class));
            verify(auditService)
                    .submitAuditEvent(
                            AUTH_ACCOUNT_TEMPORARILY_LOCKED,
                            AUDIT_CONTEXT.withSubjectId(getExpectedInternalPairwiseId()),
                            AuditService.MetadataPair.pair(
                                    "number_of_attempts_user_allowed_to_login", 5));
        }
    }

    @Test
    void shouldReturn200IfUserDoesNotExist() throws Json.JsonException {
        authSessionExists();

        setupUserProfileAndClient(Optional.empty());

        var result = handler.handleRequest(userExistsRequest(EMAIL_ADDRESS), context);

        assertThat(result, hasStatus(200));
        var checkUserExistsResponse =
                objectMapper.readValue(result.getBody(), CheckUserExistsResponse.class);
        assertThat(checkUserExistsResponse.email(), equalTo(EMAIL_ADDRESS));
        assertFalse(checkUserExistsResponse.doesUserExist());
        assertNull(authSession.getInternalCommonSubjectId());
        verify(authSessionService).updateSession(any(AuthSessionItem.class));
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_CHECK_USER_NO_ACCOUNT_WITH_EMAIL,
                        AUDIT_CONTEXT,
                        AuditService.MetadataPair.pair("rpPairwiseId", AuditService.UNKNOWN));
    }

    @Test
    void shouldReturn400IfRequestIsMissingEmail() {
        authSessionExists();

        var event = new APIGatewayProxyRequestEvent().withHeaders(VALID_HEADERS).withBody("{ }");
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.REQUEST_MISSING_PARAMS));
        verifyNoInteractions(auditService);
    }

    @Test
    void shouldReturn400IfRequestIsMissingSessionId() {
        var event = new APIGatewayProxyRequestEvent().withBody("{ }");

        var result = handler.handleRequest(event, context);

        assertEquals(400, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.SESSION_ID_MISSING));
        verifyNoInteractions(auditService);
    }

    @Test
    void shouldReturn400IfEmailAddressIsInvalid() {
        authSessionExists();

        var result = handler.handleRequest(userExistsRequest("joe.bloggs"), context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.INVALID_EMAIL_FORMAT));
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_CHECK_USER_INVALID_EMAIL,
                        AUDIT_CONTEXT.withEmail("joe.bloggs"));
    }

    @Test
    void shouldReturn400IfAuthSessionExpired() {
        authSessionMissing();

        var result = handler.handleRequest(userExistsRequest(EMAIL_ADDRESS), context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.SESSION_ID_MISSING));
    }

    private void authSessionExists() {
        when(authSessionService.getSessionFromRequestHeaders(any()))
                .thenReturn(Optional.of(authSession));
    }

    private void authSessionMissing() {
        when(authSessionService.getSessionFromRequestHeaders(any())).thenReturn(Optional.empty());
    }

    private UserProfile generateUserProfile() {
        return new UserProfile()
                .withEmail(EMAIL_ADDRESS)
                .withEmailVerified(true)
                .withPublicSubjectID(new Subject().getValue())
                .withSubjectID(SUBJECT.getValue())
                .withTermsAndConditions(
                        new TermsAndConditions("1.0", NowHelper.now().toInstant().toString()));
    }

    private static String getExpectedRpPairwiseId() {
        return ClientSubjectHelper.calculatePairwiseIdentifier(
                SUBJECT.getValue(), "sector-identifier", SALT.array());
    }

    private static String getExpectedInternalPairwiseId() {
        return ClientSubjectHelper.calculatePairwiseIdentifier(
                SUBJECT.getValue(), "test.account.gov.uk", SALT.array());
    }

    private void setupUserProfileAndClient(Optional<UserProfile> maybeUserProfile) {
        maybeUserProfile.ifPresent(
                profile ->
                        when(authenticationService.getOrGenerateSalt(profile))
                                .thenReturn(SALT.array()));
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL_ADDRESS))
                .thenReturn(maybeUserProfile);
    }

    private APIGatewayProxyRequestEvent userExistsRequest(String email) {
        return new APIGatewayProxyRequestEvent()
                .withHeaders(VALID_HEADERS)
                .withBody(format("{\"email\": \"%s\" }", email))
                .withRequestContext(contextWithSourceIp(IP_ADDRESS));
    }

    private MFAMethod verifiedMfaMethod(MFAMethodType mfaMethodType, Boolean enabled) {
        return new MFAMethod(
                mfaMethodType.getValue(),
                "some-credential-value",
                true,
                enabled,
                NowHelper.nowMinus(50, ChronoUnit.DAYS).toString());
    }

    @Nested
    class PermissionDecisionManagerErrorHandling {
        @BeforeEach
        void setup() {
            authSessionExists();
        }

        private static Stream<Arguments> decisionErrorToExpectedStatusAndErrorResponse() {
            return Stream.of(
                    Arguments.of(
                            DecisionError.STORAGE_SERVICE_ERROR,
                            500,
                            ErrorResponse.STORAGE_LAYER_ERROR),
                    Arguments.of(
                            DecisionError.INVALID_USER_CONTEXT,
                            400,
                            ErrorResponse.REQUEST_MISSING_PARAMS));
        }

        @ParameterizedTest
        @MethodSource("decisionErrorToExpectedStatusAndErrorResponse")
        void shouldReturnCorrectErrorResponseForCanReceivePasswordFailure(
                DecisionError decisionError,
                int expectedStatusCode,
                ErrorResponse expectedErrorResponse) {
            when(permissionDecisionManager.canReceivePassword(any(), any(), any(), any(), any()))
                    .thenReturn(Result.failure(decisionError));

            var result = handler.handleRequest(userExistsRequest(EMAIL_ADDRESS), context);

            assertThat(result, hasStatus(expectedStatusCode));
            assertThat(result, hasJsonBody(expectedErrorResponse));
        }

        private static Stream<Arguments> decisionErrorToExpectedErrorResponse() {
            return Stream.of(
                    Arguments.of(
                            DecisionError.STORAGE_SERVICE_ERROR,
                            ErrorResponse.STORAGE_LAYER_ERROR));
        }

        @ParameterizedTest
        @MethodSource("decisionErrorToExpectedErrorResponse")
        void shouldReturnCorrectErrorResponseForCanVerifyMfaOtpFailure(
                DecisionError decisionError, ErrorResponse expectedErrorResponse) {
            setupUserProfileAndClient(Optional.of(generateUserProfile()));
            when(authenticationService.getUserCredentialsFromEmail(EMAIL_ADDRESS))
                    .thenReturn(new UserCredentials().withMfaMethods(List.of()));
            when(permissionDecisionManager.canVerifyMfaOtp(
                            eq(JourneyType.SIGN_IN), any(), any(), any()))
                    .thenReturn(Result.failure(decisionError));

            var result = handler.handleRequest(userExistsRequest(EMAIL_ADDRESS), context);

            assertThat(result, hasStatus(500));
            assertThat(result, hasJsonBody(ErrorResponse.STORAGE_LAYER_ERROR));
        }
    }
}

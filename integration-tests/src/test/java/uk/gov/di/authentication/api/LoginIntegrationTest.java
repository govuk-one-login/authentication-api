package uk.gov.di.authentication.api;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.frontendapi.entity.LoginRequest;
import uk.gov.di.authentication.frontendapi.entity.LoginResponse;
import uk.gov.di.authentication.frontendapi.entity.mfa.MfaMethodResponse;
import uk.gov.di.authentication.frontendapi.lambda.LoginHandler;
import uk.gov.di.authentication.frontendapi.serialization.MfaMethodResponseAdapter;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.AuthSessionExtension;
import uk.gov.di.authentication.sharedtest.extensions.AuthenticationAttemptsStoreExtension;
import uk.gov.di.authentication.sharedtest.extensions.InternationalSmsSendCountExtension;
import uk.gov.di.authentication.sharedtest.helper.AuditEventExpectation;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_ACCOUNT_TEMPORARILY_LOCKED;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_INVALID_CREDENTIALS;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_LOG_IN_SUCCESS;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_REAUTH_FAILED;
import static uk.gov.di.authentication.shared.entity.CredentialTrustLevel.LOW_LEVEL;
import static uk.gov.di.authentication.shared.entity.CredentialTrustLevel.MEDIUM_LEVEL;
import static uk.gov.di.authentication.shared.entity.mfa.MFAMethodType.AUTH_APP;
import static uk.gov.di.authentication.shared.entity.mfa.MFAMethodType.NONE;
import static uk.gov.di.authentication.shared.entity.mfa.MFAMethodType.SMS;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.INTERNATIONAL_MOBILE_NUMBER;
import static uk.gov.di.authentication.shared.helpers.TxmaAuditHelper.TXMA_AUDIT_ENCODED_HEADER;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertAuditEventExpectations;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertTxmaAuditEventsReceived;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;
import static uk.gov.di.authentication.testsupport.AuditTestConstants.ATTEMPT_NO_FAILED_AT;
import static uk.gov.di.authentication.testsupport.AuditTestConstants.FAILURE_REASON;
import static uk.gov.di.authentication.testsupport.AuditTestConstants.INCORRECT_EMAIL_ATTEMPT_COUNT;
import static uk.gov.di.authentication.testsupport.AuditTestConstants.INCORRECT_OTP_CODE_ATTEMPT_COUNT;
import static uk.gov.di.authentication.testsupport.AuditTestConstants.INCORRECT_PASSWORD_ATTEMPT_COUNT;
import static uk.gov.di.authentication.testsupport.AuditTestConstants.INCORRECT_PASSWORD_COUNT;
import static uk.gov.di.authentication.testsupport.AuditTestConstants.INTERNAL_SUBJECT_ID;
import static uk.gov.di.authentication.testsupport.AuditTestConstants.NUMBER_OF_ATTEMPTS_USER_ALLOWED_TO_LOGIN;
import static uk.gov.di.authentication.testsupport.AuditTestConstants.RP_PAIRWISE_ID;

public class LoginIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String CLIENT_ID = "test-client-id";
    public static final String CLIENT_SESSION_ID = "a-client-session-id";
    private static final String CURRENT_TERMS_AND_CONDITIONS = "1.0";
    private static final String OLD_TERMS_AND_CONDITIONS = "0.1";
    public static final String CLIENT_NAME = "test-client-name";
    public static final String ENCODED_DEVICE_INFORMATION =
            "R21vLmd3QilNKHJsaGkvTFxhZDZrKF44SStoLFsieG0oSUY3aEhWRVtOMFRNMVw1dyInKzB8OVV5N09hOi8kLmlLcWJjJGQiK1NPUEJPPHBrYWJHP358NDg2ZDVc";
    private final AuthSessionExtension authSessionExtension = new AuthSessionExtension();
    private static final String SECTOR_IDENTIFIER_HOST = "test.com";
    private static final String TEST_REFERENCE = "test-reference";
    protected final Json objectMapper =
            new SerializationService(
                    Map.of(MfaMethodResponse.class, new MfaMethodResponseAdapter()));

    private CodeStorageService codeStorageService;

    @BeforeEach
    void setup() {
        handler =
                new LoginHandler(
                        REAUTH_SIGNOUT_AND_TXMA_ENABLED_CONFIGUARION_SERVICE,
                        redisConnectionService);
        codeStorageService =
                new CodeStorageService(
                        REAUTH_SIGNOUT_AND_TXMA_ENABLED_CONFIGUARION_SERVICE,
                        redisConnectionService);
        txmaAuditQueue.clear();
    }

    @RegisterExtension
    protected static final AuthenticationAttemptsStoreExtension authCodeExtension =
            new AuthenticationAttemptsStoreExtension();

    @RegisterExtension
    protected static final InternationalSmsSendCountExtension internationalSmsSendLimit =
            new InternationalSmsSendCountExtension(10);

    @Nested
    class SuccessfulLoginScenarios {

        private static Stream<Arguments> vectorOfTrust() {
            return Stream.of(
                    Arguments.of(null, CURRENT_TERMS_AND_CONDITIONS, SMS, true),
                    Arguments.of(LOW_LEVEL, CURRENT_TERMS_AND_CONDITIONS, SMS, true),
                    Arguments.of(MEDIUM_LEVEL, CURRENT_TERMS_AND_CONDITIONS, SMS, true),
                    Arguments.of(null, OLD_TERMS_AND_CONDITIONS, SMS, true),
                    Arguments.of(LOW_LEVEL, OLD_TERMS_AND_CONDITIONS, SMS, true),
                    Arguments.of(MEDIUM_LEVEL, OLD_TERMS_AND_CONDITIONS, SMS, true),
                    Arguments.of(null, CURRENT_TERMS_AND_CONDITIONS, SMS, false),
                    Arguments.of(LOW_LEVEL, CURRENT_TERMS_AND_CONDITIONS, SMS, false),
                    Arguments.of(MEDIUM_LEVEL, CURRENT_TERMS_AND_CONDITIONS, SMS, false),
                    Arguments.of(null, OLD_TERMS_AND_CONDITIONS, SMS, false),
                    Arguments.of(LOW_LEVEL, OLD_TERMS_AND_CONDITIONS, SMS, false),
                    Arguments.of(MEDIUM_LEVEL, OLD_TERMS_AND_CONDITIONS, SMS, false),
                    Arguments.of(null, CURRENT_TERMS_AND_CONDITIONS, AUTH_APP, true),
                    Arguments.of(LOW_LEVEL, CURRENT_TERMS_AND_CONDITIONS, AUTH_APP, true),
                    Arguments.of(MEDIUM_LEVEL, CURRENT_TERMS_AND_CONDITIONS, AUTH_APP, true),
                    Arguments.of(null, OLD_TERMS_AND_CONDITIONS, AUTH_APP, true),
                    Arguments.of(LOW_LEVEL, OLD_TERMS_AND_CONDITIONS, AUTH_APP, true),
                    Arguments.of(MEDIUM_LEVEL, OLD_TERMS_AND_CONDITIONS, AUTH_APP, true),
                    Arguments.of(null, CURRENT_TERMS_AND_CONDITIONS, AUTH_APP, false),
                    Arguments.of(LOW_LEVEL, CURRENT_TERMS_AND_CONDITIONS, AUTH_APP, false),
                    Arguments.of(MEDIUM_LEVEL, CURRENT_TERMS_AND_CONDITIONS, AUTH_APP, false),
                    Arguments.of(null, OLD_TERMS_AND_CONDITIONS, AUTH_APP, false),
                    Arguments.of(LOW_LEVEL, OLD_TERMS_AND_CONDITIONS, AUTH_APP, false),
                    Arguments.of(MEDIUM_LEVEL, OLD_TERMS_AND_CONDITIONS, AUTH_APP, false));
        }

        @ParameterizedTest
        @MethodSource("vectorOfTrust")
        void shouldSuccessfullyProcessLoginRequestForDifferentVectorOfTrusts(
                CredentialTrustLevel level,
                String termsAndConditionsVersion,
                MFAMethodType mfaMethodType,
                boolean mfaMethodVerified)
                throws Json.JsonException {
            var email = "joe.bloggs+3@digital.cabinet-office.gov.uk";
            var password = "password-1";
            var sessionId = IdGenerator.generate();
            authSessionExtension.addSession(sessionId);
            authSessionExtension.addEmailToSession(sessionId, email);
            authSessionExtension.addClientIdToSession(sessionId, CLIENT_ID);
            authSessionExtension.addRequestedCredentialStrengthToSession(sessionId, level);
            authSessionExtension.addClientNameToSession(sessionId, CLIENT_NAME);
            authSessionExtension.addRpSectorIdentifierHostToSession(
                    sessionId, SECTOR_IDENTIFIER_HOST);

            userStore.signUp(email, password);
            userStore.updateTermsAndConditions(email, termsAndConditionsVersion);
            if (mfaMethodType.equals(SMS)) {
                userStore.setPhoneNumberAndVerificationStatus(
                        email, "01234567890", mfaMethodVerified, mfaMethodVerified);
            } else {
                userStore.updateMFAMethod(
                        email, mfaMethodType, mfaMethodVerified, true, "auth-app-credential");
            }

            var headers = validHeadersWithSessionId(sessionId);

            var response =
                    makeRequest(
                            Optional.of(new LoginRequest(email, password, JourneyType.SIGN_IN)),
                            headers,
                            Map.of());
            assertThat(response, hasStatus(200));

            var loginResponse = objectMapper.readValue(response.getBody(), LoginResponse.class);

            assertThat(loginResponse.mfaRequired(), equalTo(level != LOW_LEVEL));
            assertThat(
                    loginResponse.latestTermsAndConditionsAccepted(),
                    equalTo(termsAndConditionsVersion.equals(CURRENT_TERMS_AND_CONDITIONS)));

            var expectedMfaType =
                    (mfaMethodType.equals(SMS) && !mfaMethodVerified) ? NONE : mfaMethodType;
            assertThat(loginResponse.mfaMethodType(), equalTo(expectedMfaType));
            assertThat(loginResponse.mfaMethodVerified(), equalTo(mfaMethodVerified));
            assertTrue(
                    Objects.nonNull(
                            authSessionExtension
                                    .getSession(sessionId)
                                    .orElseThrow()
                                    .getInternalCommonSubjectId()));
            assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(AUTH_LOG_IN_SUCCESS));
        }

        private static Stream<Arguments> vectorOfTrustWithVerifiedMethods() {
            return Stream.of(
                    Arguments.of(null, CURRENT_TERMS_AND_CONDITIONS, SMS),
                    Arguments.of(LOW_LEVEL, CURRENT_TERMS_AND_CONDITIONS, SMS),
                    Arguments.of(MEDIUM_LEVEL, CURRENT_TERMS_AND_CONDITIONS, SMS),
                    Arguments.of(null, OLD_TERMS_AND_CONDITIONS, SMS),
                    Arguments.of(LOW_LEVEL, OLD_TERMS_AND_CONDITIONS, SMS),
                    Arguments.of(MEDIUM_LEVEL, OLD_TERMS_AND_CONDITIONS, SMS),
                    Arguments.of(null, CURRENT_TERMS_AND_CONDITIONS, SMS, false),
                    Arguments.of(null, CURRENT_TERMS_AND_CONDITIONS, AUTH_APP),
                    Arguments.of(LOW_LEVEL, CURRENT_TERMS_AND_CONDITIONS, AUTH_APP),
                    Arguments.of(MEDIUM_LEVEL, CURRENT_TERMS_AND_CONDITIONS, AUTH_APP),
                    Arguments.of(null, OLD_TERMS_AND_CONDITIONS, AUTH_APP),
                    Arguments.of(LOW_LEVEL, OLD_TERMS_AND_CONDITIONS, AUTH_APP),
                    Arguments.of(MEDIUM_LEVEL, OLD_TERMS_AND_CONDITIONS, AUTH_APP));
        }

        @ParameterizedTest
        @MethodSource(
                "vectorOfTrustWithVerifiedMethods") // We are only going to migrate verified mfa
        // methods
        void shouldSuccessfullyProcessLoginRequestForDifferentVectorOfTrustsAndAMigratedUser(
                CredentialTrustLevel level,
                String termsAndConditionsVersion,
                MFAMethodType mfaMethodType)
                throws Json.JsonException {
            var email = "joe.bloggs+3@digital.cabinet-office.gov.uk";
            var password = "password-1";
            var sessionId = IdGenerator.generate();
            authSessionExtension.addSession(sessionId);
            authSessionExtension.addEmailToSession(sessionId, email);
            authSessionExtension.addClientIdToSession(sessionId, CLIENT_ID);
            authSessionExtension.addRequestedCredentialStrengthToSession(sessionId, level);
            authSessionExtension.addClientNameToSession(sessionId, CLIENT_NAME);
            authSessionExtension.addRpSectorIdentifierHostToSession(
                    sessionId, SECTOR_IDENTIFIER_HOST);

            userStore.signUp(email, password);
            userStore.updateTermsAndConditions(email, termsAndConditionsVersion);
            userStore.setMfaMethodsMigrated(email, true);
            if (mfaMethodType.equals(SMS)) {
                userStore.addMfaMethodSupportingMultiple(
                        email,
                        MFAMethod.smsMfaMethod(
                                true,
                                true,
                                "01234567890",
                                PriorityIdentifier.DEFAULT,
                                "some-mfa-id"));
            } else {
                userStore.addMfaMethodSupportingMultiple(
                        email,
                        MFAMethod.authAppMfaMethod(
                                "some-credential",
                                true,
                                true,
                                PriorityIdentifier.DEFAULT,
                                "some-mfa-id"));
            }

            var headers = validHeadersWithSessionId(sessionId);

            var response =
                    makeRequest(
                            Optional.of(new LoginRequest(email, password, JourneyType.SIGN_IN)),
                            headers,
                            Map.of());
            assertThat(response, hasStatus(200));

            var loginResponse = objectMapper.readValue(response.getBody(), LoginResponse.class);

            assertThat(loginResponse.mfaRequired(), equalTo(level != LOW_LEVEL));
            assertThat(
                    loginResponse.latestTermsAndConditionsAccepted(),
                    equalTo(termsAndConditionsVersion.equals(CURRENT_TERMS_AND_CONDITIONS)));

            assertThat(loginResponse.mfaMethodType(), equalTo(mfaMethodType));
            assertThat(loginResponse.mfaMethodVerified(), equalTo(true));
            assertTrue(
                    Objects.nonNull(
                            authSessionExtension
                                    .getSession(sessionId)
                                    .orElseThrow()
                                    .getInternalCommonSubjectId()));
            assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(AUTH_LOG_IN_SUCCESS));
        }

        @Test
        void shouldUpdateAuthSessionStoreWithExistingAccountStateWhenSuccessful() {
            var email = "joe.bloggs+3@digital.cabinet-office.gov.uk";
            var password = "password-1";
            var sessionId = IdGenerator.generate();
            authSessionExtension.addSession(sessionId);
            authSessionExtension.addEmailToSession(sessionId, email);
            authSessionExtension.addClientIdToSession(sessionId, CLIENT_ID);
            authSessionExtension.addRpSectorIdentifierHostToSession(
                    sessionId, SECTOR_IDENTIFIER_HOST);

            userStore.signUp(email, password);
            userStore.updateTermsAndConditions(email, CURRENT_TERMS_AND_CONDITIONS);
            userStore.setPhoneNumberAndVerificationStatus(email, "01234567890", true, true);

            var response =
                    makeRequest(
                            Optional.of(new LoginRequest(email, password, JourneyType.SIGN_IN)),
                            validHeadersWithSessionId(sessionId),
                            Map.of());
            assertThat(response, hasStatus(200));
            assertThat(
                    authSessionExtension.getSession(sessionId).get().getIsNewAccount(),
                    equalTo(AuthSessionItem.AccountState.EXISTING));
        }

        @Test
        void shouldReturn400WhenInternationalNumberIsLockedOut() throws Json.JsonException {
            var email = "joe.bloggs+intl@digital.cabinet-office.gov.uk";
            var password = "password-1";
            var sessionId = IdGenerator.generate();
            authSessionExtension.addSession(sessionId);
            authSessionExtension.addEmailToSession(sessionId, email);
            authSessionExtension.addClientIdToSession(sessionId, CLIENT_ID);
            authSessionExtension.addRequestedCredentialStrengthToSession(sessionId, MEDIUM_LEVEL);
            authSessionExtension.addClientNameToSession(sessionId, CLIENT_NAME);
            authSessionExtension.addRpSectorIdentifierHostToSession(
                    sessionId, SECTOR_IDENTIFIER_HOST);

            userStore.signUp(email, password);
            userStore.updateTermsAndConditions(email, CURRENT_TERMS_AND_CONDITIONS);
            userStore.setPhoneNumberAndVerificationStatus(
                    email, INTERNATIONAL_MOBILE_NUMBER, true, true);

            for (int i = 0; i < 10; i++) {
                internationalSmsSendLimit.recordSmsSent(
                        INTERNATIONAL_MOBILE_NUMBER, TEST_REFERENCE);
            }

            var response =
                    makeRequest(
                            Optional.of(new LoginRequest(email, password, JourneyType.SIGN_IN)),
                            validHeadersWithSessionId(sessionId),
                            Map.of());

            assertThat(response, hasStatus(400));
            assertThat(
                    response,
                    hasBody(
                            objectMapper.writeValueAsString(
                                    ErrorResponse.INDEFINITELY_BLOCKED_SENDING_INT_NUMBERS_SMS)));
        }

        @Test
        void shouldSuccessfullyLoginWithInternationalNumberWhenNotLockedOut()
                throws Json.JsonException {
            var email = "joe.bloggs+intl2@digital.cabinet-office.gov.uk";
            var password = "password-1";
            var sessionId = IdGenerator.generate();
            authSessionExtension.addSession(sessionId);
            authSessionExtension.addEmailToSession(sessionId, email);
            authSessionExtension.addClientIdToSession(sessionId, CLIENT_ID);
            authSessionExtension.addRequestedCredentialStrengthToSession(sessionId, MEDIUM_LEVEL);
            authSessionExtension.addClientNameToSession(sessionId, CLIENT_NAME);
            authSessionExtension.addRpSectorIdentifierHostToSession(
                    sessionId, SECTOR_IDENTIFIER_HOST);

            userStore.signUp(email, password);
            userStore.updateTermsAndConditions(email, CURRENT_TERMS_AND_CONDITIONS);
            userStore.setPhoneNumberAndVerificationStatus(
                    email, INTERNATIONAL_MOBILE_NUMBER, true, true);

            var response =
                    makeRequest(
                            Optional.of(new LoginRequest(email, password, JourneyType.SIGN_IN)),
                            validHeadersWithSessionId(sessionId),
                            Map.of());

            assertThat(response, hasStatus(200));

            var loginResponse = objectMapper.readValue(response.getBody(), LoginResponse.class);
            assertThat(loginResponse.mfaRequired(), equalTo(true));
            assertThat(loginResponse.mfaMethodType(), equalTo(SMS));
            assertThat(loginResponse.mfaMethodVerified(), equalTo(true));
            assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(AUTH_LOG_IN_SUCCESS));
        }
    }

    @Nested
    class InvalidCredentialsScenarios {

        @Test
        void shouldCallLoginEndpointAndReturn401henUserHasInvalidCredentials() {
            String email = "joe.bloggs+4@digital.cabinet-office.gov.uk";
            String password = "password-1";
            userStore.signUp(email, "wrong-password");

            var sessionId = IdGenerator.generate();
            authSessionExtension.addSession(sessionId);
            authSessionExtension.addEmailToSession(sessionId, email);
            authSessionExtension.addClientIdToSession(sessionId, CLIENT_ID);
            authSessionExtension.addRpSectorIdentifierHostToSession(
                    sessionId, SECTOR_IDENTIFIER_HOST);
            var headers = validHeadersWithSessionId(sessionId);

            var response =
                    makeRequest(
                            Optional.of(new LoginRequest(email, password, JourneyType.SIGN_IN)),
                            headers,
                            Map.of());
            assertThat(response, hasStatus(401));
            assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(AUTH_INVALID_CREDENTIALS));
        }
    }

    @Nested
    class AccountLockoutScenarios {

        @ParameterizedTest
        @EnumSource(
                value = JourneyType.class,
                names = {"SIGN_IN", "REAUTHENTICATION"})
        void shouldLockoutUserAfter6AttemptsAndRejectValidCredentials(JourneyType journeyType) {
            String email =
                    "joe.bloggs+"
                            + journeyType.name().toLowerCase()
                            + "@digital.cabinet-office.gov.uk";
            String correctPassword = "correct-password";
            userStore.signUp(email, correctPassword);
            var sessionId = IdGenerator.generate();
            authSessionExtension.addSession(sessionId);
            authSessionExtension.addEmailToSession(sessionId, email);
            authSessionExtension.addClientIdToSession(sessionId, CLIENT_ID);
            authSessionExtension.addRpSectorIdentifierHostToSession(
                    sessionId, SECTOR_IDENTIFIER_HOST);
            var userProfile = userStore.getUserProfileFromEmail(email).orElseThrow();
            byte[] salt = userStore.addSalt(email);
            String rpPairwiseId =
                    ClientSubjectHelper.calculatePairwiseIdentifier(
                            userProfile.getSubjectID(), SECTOR_IDENTIFIER_HOST, salt);

            boolean isReauth = journeyType.equals(JourneyType.REAUTHENTICATION);
            AuditEventExpectation reauthFailedEventExpectation =
                    new AuditEventExpectation(AUTH_REAUTH_FAILED)
                            .withAttribute(INCORRECT_EMAIL_ATTEMPT_COUNT, "0")
                            .withAttribute(INCORRECT_OTP_CODE_ATTEMPT_COUNT, "0")
                            .withAttribute(INCORRECT_PASSWORD_ATTEMPT_COUNT, "6")
                            .withAttribute(FAILURE_REASON, "incorrect_password")
                            .withAttribute(RP_PAIRWISE_ID, rpPairwiseId);
            AuditEventExpectation lockoutEventExpectation =
                    new AuditEventExpectation(AUTH_ACCOUNT_TEMPORARILY_LOCKED)
                            .withAttribute(INTERNAL_SUBJECT_ID, userProfile.getSubjectID())
                            .withAttribute(ATTEMPT_NO_FAILED_AT, "6")
                            .withAttribute(NUMBER_OF_ATTEMPTS_USER_ALLOWED_TO_LOGIN, "6");
            AuditEventExpectation invalidCredentialsEventExpectation =
                    new AuditEventExpectation(AUTH_INVALID_CREDENTIALS)
                            .withAttribute(INCORRECT_PASSWORD_COUNT, "6")
                            .withAttribute(ATTEMPT_NO_FAILED_AT, "6");

            var headers = validHeadersWithSessionId(sessionId);

            var wrongRequest = new LoginRequest(email, "wrong-password", journeyType);

            IntStream.rangeClosed(1, 5)
                    .forEach(
                            attemptNumber -> {
                                var response =
                                        makeRequest(Optional.of(wrongRequest), headers, Map.of());
                                assertThat(response, hasStatus(401));
                                assertAuditEventExpectations(
                                        txmaAuditQueue,
                                        List.of(
                                                new AuditEventExpectation(
                                                                invalidCredentialsEventExpectation)
                                                        .withAttribute(
                                                                INCORRECT_PASSWORD_COUNT,
                                                                String.valueOf(attemptNumber))));
                            });

            var sixthResponse = makeRequest(Optional.of(wrongRequest), headers, Map.of());
            assertThat(sixthResponse, hasStatus(400));
            assertThat(
                    sixthResponse,
                    hasJsonBody(
                            isReauth
                                    ? ErrorResponse.TOO_MANY_INVALID_REAUTH_ATTEMPTS
                                    : ErrorResponse.TOO_MANY_INVALID_PW_ENTERED));
            assertAuditEventExpectations(
                    txmaAuditQueue,
                    List.of(
                            new AuditEventExpectation(invalidCredentialsEventExpectation)
                                    .withAttribute(INCORRECT_PASSWORD_COUNT, "6"),
                            isReauth ? reauthFailedEventExpectation : lockoutEventExpectation));

            var validRequest = new LoginRequest(email, correctPassword, journeyType);
            var validResponse = makeRequest(Optional.of(validRequest), headers, Map.of());
            assertThat(validResponse, hasStatus(400));
            assertThat(
                    validResponse,
                    hasJsonBody(
                            isReauth
                                    ? ErrorResponse.TOO_MANY_INVALID_REAUTH_ATTEMPTS
                                    : ErrorResponse.TOO_MANY_INVALID_PW_ENTERED));
            assertAuditEventExpectations(
                    txmaAuditQueue,
                    List.of(isReauth ? reauthFailedEventExpectation : lockoutEventExpectation));
        }

        @Test
        void shouldReturn400WhenUserIsBlockedFromRequestingMfaCodes() {
            String email = "joe.bloggs+mfa1@digital.cabinet-office.gov.uk";
            String password = "password-1";
            userStore.signUp(email, password);
            userStore.addMfaMethod(email, MFAMethodType.SMS, true, true, "credential");

            var sessionId = IdGenerator.generate();
            authSessionExtension.addSession(sessionId);
            authSessionExtension.addEmailToSession(sessionId, email);
            authSessionExtension.addClientIdToSession(sessionId, CLIENT_ID);
            authSessionExtension.addRpSectorIdentifierHostToSession(
                    sessionId, SECTOR_IDENTIFIER_HOST);
            var headers = validHeadersWithSessionId(sessionId);

            codeStorageService.saveBlockedForEmail(email, "code-request-blocked:MFA_SIGN_IN", 900);

            var request = new LoginRequest(email, password, JourneyType.SIGN_IN);
            var response = makeRequest(Optional.of(request), headers, Map.of());

            assertThat(response, hasStatus(400));
            assertThat(response, hasJsonBody(ErrorResponse.BLOCKED_FOR_SENDING_MFA_OTPS));
        }

        @Test
        void shouldReturn400WhenUserIsBlockedFromEnteringMfaCodes() {
            String email = "joe.bloggs+mfa2@digital.cabinet-office.gov.uk";
            String password = "password-1";
            userStore.signUp(email, password);
            userStore.addMfaMethod(email, MFAMethodType.SMS, true, true, "credential");

            var sessionId = IdGenerator.generate();
            authSessionExtension.addSession(sessionId);
            authSessionExtension.addEmailToSession(sessionId, email);
            authSessionExtension.addClientIdToSession(sessionId, CLIENT_ID);
            authSessionExtension.addRpSectorIdentifierHostToSession(
                    sessionId, SECTOR_IDENTIFIER_HOST);
            var headers = validHeadersWithSessionId(sessionId);

            codeStorageService.saveBlockedForEmail(email, "code-blocked:MFA_SIGN_IN", 900);

            var request = new LoginRequest(email, password, JourneyType.SIGN_IN);
            var response = makeRequest(Optional.of(request), headers, Map.of());

            assertThat(response, hasStatus(400));
            assertThat(response, hasJsonBody(ErrorResponse.TOO_MANY_INVALID_MFA_OTPS_ENTERED));
        }
    }

    private Map<String, String> validHeadersWithSessionId(String sessionId) {
        return Map.ofEntries(
                Map.entry("Session-Id", sessionId),
                Map.entry("X-API-Key", FRONTEND_API_KEY),
                Map.entry("Client-Session-Id", CLIENT_SESSION_ID),
                Map.entry(TXMA_AUDIT_ENCODED_HEADER, ENCODED_DEVICE_INFORMATION));
    }
}

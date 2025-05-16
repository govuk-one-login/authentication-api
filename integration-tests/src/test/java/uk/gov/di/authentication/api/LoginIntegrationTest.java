package uk.gov.di.authentication.api;

import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.frontendapi.entity.LoginRequest;
import uk.gov.di.authentication.frontendapi.entity.LoginResponse;
import uk.gov.di.authentication.frontendapi.entity.mfa.MfaMethodResponse;
import uk.gov.di.authentication.frontendapi.lambda.LoginHandler;
import uk.gov.di.authentication.frontendapi.serialization.MfaMethodResponseAdapter;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.ServiceType;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.AuthSessionExtension;
import uk.gov.di.authentication.sharedtest.extensions.AuthenticationAttemptsStoreExtension;

import java.net.URI;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Stream;

import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_ACCOUNT_TEMPORARILY_LOCKED;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_INVALID_CREDENTIALS;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_LOG_IN_SUCCESS;
import static uk.gov.di.authentication.shared.entity.CredentialTrustLevel.LOW_LEVEL;
import static uk.gov.di.authentication.shared.entity.CredentialTrustLevel.MEDIUM_LEVEL;
import static uk.gov.di.authentication.shared.entity.mfa.MFAMethodType.AUTH_APP;
import static uk.gov.di.authentication.shared.entity.mfa.MFAMethodType.NONE;
import static uk.gov.di.authentication.shared.entity.mfa.MFAMethodType.SMS;
import static uk.gov.di.authentication.shared.helpers.TxmaAuditHelper.TXMA_AUDIT_ENCODED_HEADER;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertTxmaAuditEventsReceived;
import static uk.gov.di.authentication.sharedtest.helper.JsonArrayHelper.jsonArrayOf;
import static uk.gov.di.authentication.sharedtest.helper.KeyPairHelper.GENERATE_RSA_KEY_PAIR;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class LoginIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String CLIENT_ID = "test-client-id";
    private static final String REDIRECT_URI = "http://localhost/redirect";
    public static final String CLIENT_SESSION_ID = "a-client-session-id";
    private static final String CURRENT_TERMS_AND_CONDITIONS = "1.0";
    private static final String OLD_TERMS_AND_CONDITIONS = "0.1";
    public static final String CLIENT_NAME = "test-client-name";
    public static final String ENCODED_DEVICE_INFORMATION =
            "R21vLmd3QilNKHJsaGkvTFxhZDZrKF44SStoLFsieG0oSUY3aEhWRVtOMFRNMVw1dyInKzB8OVV5N09hOi8kLmlLcWJjJGQiK1NPUEJPPHBrYWJHP358NDg2ZDVc";
    private final AuthSessionExtension authSessionExtension = new AuthSessionExtension();
    private static final Scope SCOPE = new Scope(OIDCScopeValue.OPENID);
    private static AuthenticationRequest.Builder basicAuthRequestBuilder =
            new AuthenticationRequest.Builder(
                            ResponseType.CODE,
                            SCOPE,
                            new ClientID(CLIENT_ID),
                            URI.create(REDIRECT_URI))
                    .nonce(new Nonce());
    protected final Json objectMapper =
            new SerializationService(
                    Map.of(MfaMethodResponse.class, new MfaMethodResponseAdapter()));

    @BeforeEach
    void setup() {
        handler = new LoginHandler(TXMA_ENABLED_CONFIGURATION_SERVICE, redisConnectionService);
        txmaAuditQueue.clear();

        clientStore.registerClient(
                CLIENT_ID,
                "The test client",
                singletonList(REDIRECT_URI),
                singletonList("test-client@test.com"),
                singletonList(SCOPE.toString()),
                Base64.getMimeEncoder()
                        .encodeToString(GENERATE_RSA_KEY_PAIR().getPublic().getEncoded()),
                singletonList("http://localhost/post-redirect-logout"),
                "http://example.com",
                String.valueOf(ServiceType.MANDATORY),
                "https://test.com",
                "public");
    }

    @RegisterExtension
    protected static final AuthenticationAttemptsStoreExtension authCodeExtension =
            new AuthenticationAttemptsStoreExtension();

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
        redis.createSession(sessionId);
        authSessionExtension.addSession(sessionId);
        authSessionExtension.addEmailToSession(sessionId, email);
        authSessionExtension.addClientIdToSession(sessionId, CLIENT_ID);

        userStore.signUp(email, password);
        userStore.updateTermsAndConditions(email, termsAndConditionsVersion);
        if (mfaMethodType.equals(SMS)) {
            userStore.setPhoneNumberAndVerificationStatus(
                    email, "01234567890", mfaMethodVerified, mfaMethodVerified);
        } else {
            userStore.updateMFAMethod(
                    email, mfaMethodType, mfaMethodVerified, true, "auth-app-credential");
        }

        AuthenticationRequest.Builder builder = basicAuthRequestBuilder;
        if (level != null) {
            builder.customParameter("vtr", jsonArrayOf(level.getValue()));
        }
        redis.createClientSession(CLIENT_SESSION_ID, CLIENT_NAME, builder.build().toParameters());

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

    @ParameterizedTest
    @MethodSource(
            "vectorOfTrustWithVerifiedMethods") // We are only going to migrate verified mfa methods
    void shouldSuccessfullyProcessLoginRequestForDifferentVectorOfTrustsAndAMigratedUser(
            CredentialTrustLevel level,
            String termsAndConditionsVersion,
            MFAMethodType mfaMethodType)
            throws Json.JsonException {
        var email = "joe.bloggs+3@digital.cabinet-office.gov.uk";
        var password = "password-1";
        var sessionId = IdGenerator.generate();
        redis.createSession(sessionId);
        authSessionExtension.addSession(sessionId);
        authSessionExtension.addEmailToSession(sessionId, email);
        authSessionExtension.addClientIdToSession(sessionId, CLIENT_ID);

        userStore.signUp(email, password);
        userStore.updateTermsAndConditions(email, termsAndConditionsVersion);
        userStore.setMfaMethodsMigrated(email, true);
        if (mfaMethodType.equals(SMS)) {
            userStore.addMfaMethodSupportingMultiple(
                    email,
                    MFAMethod.smsMfaMethod(
                            true, true, "01234567890", PriorityIdentifier.DEFAULT, "some-mfa-id"));
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

        AuthenticationRequest.Builder builder = basicAuthRequestBuilder;
        if (level != null) {
            builder.customParameter("vtr", jsonArrayOf(level.getValue()));
        }
        redis.createClientSession(CLIENT_SESSION_ID, CLIENT_NAME, builder.build().toParameters());

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

    @Test
    void shouldUpdateAuthSessionStoreWithExistingAccountStateWhenSuccessful()
            throws Json.JsonException {
        var email = "joe.bloggs+3@digital.cabinet-office.gov.uk";
        var password = "password-1";
        var sessionId = IdGenerator.generate();
        redis.createSession(sessionId);
        authSessionExtension.addSession(sessionId);
        authSessionExtension.addEmailToSession(sessionId, email);
        authSessionExtension.addClientIdToSession(sessionId, CLIENT_ID);

        userStore.signUp(email, password);
        userStore.updateTermsAndConditions(email, CURRENT_TERMS_AND_CONDITIONS);
        userStore.setPhoneNumberAndVerificationStatus(email, "01234567890", true, true);

        redis.createClientSession(
                CLIENT_SESSION_ID, CLIENT_NAME, basicAuthRequestBuilder.build().toParameters());

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
    void shouldCallLoginEndpointAndReturn401henUserHasInvalidCredentials()
            throws Json.JsonException {
        String email = "joe.bloggs+4@digital.cabinet-office.gov.uk";
        String password = "password-1";
        userStore.signUp(email, "wrong-password");

        var sessionId = IdGenerator.generate();
        redis.createSession(sessionId);
        authSessionExtension.addSession(sessionId);
        authSessionExtension.addEmailToSession(sessionId, email);
        authSessionExtension.addClientIdToSession(sessionId, CLIENT_ID);
        redis.createClientSession(
                CLIENT_SESSION_ID, CLIENT_NAME, basicAuthRequestBuilder.build().toParameters());
        var headers = validHeadersWithSessionId(sessionId);

        var response =
                makeRequest(
                        Optional.of(new LoginRequest(email, password, JourneyType.SIGN_IN)),
                        headers,
                        Map.of());
        assertThat(response, hasStatus(401));
        assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(AUTH_INVALID_CREDENTIALS));
    }

    @Test
    void shouldCallLoginEndpoint6TimesAndReturn400WhenUserIdLockedOut() throws Json.JsonException {
        String email = "joe.bloggs+4@digital.cabinet-office.gov.uk";
        String password = "password-1";
        userStore.signUp(email, "wrong-password");
        var sessionId = IdGenerator.generate();
        redis.createSession(sessionId);
        authSessionExtension.addSession(sessionId);
        authSessionExtension.addEmailToSession(sessionId, email);
        authSessionExtension.addClientIdToSession(sessionId, CLIENT_ID);
        var headers = validHeadersWithSessionId(sessionId);

        redis.createClientSession(
                CLIENT_SESSION_ID, CLIENT_NAME, basicAuthRequestBuilder.build().toParameters());

        var request = new LoginRequest(email, password, JourneyType.SIGN_IN);

        for (int i = 0; i < 5; i++) {
            var response = makeRequest(Optional.of(request), headers, Map.of());
            assertThat(response, hasStatus(401));
        }

        var response = makeRequest(Optional.of(request), headers, Map.of());
        assertThat(response, hasStatus(400));

        assertTxmaAuditEventsReceived(
                txmaAuditQueue,
                List.of(
                        AUTH_ACCOUNT_TEMPORARILY_LOCKED,
                        AUTH_INVALID_CREDENTIALS,
                        AUTH_INVALID_CREDENTIALS,
                        AUTH_INVALID_CREDENTIALS,
                        AUTH_INVALID_CREDENTIALS,
                        AUTH_INVALID_CREDENTIALS,
                        AUTH_INVALID_CREDENTIALS));
    }

    @Test
    void shouldCallLoginEndpoint6TimesAndReturn400TwiceWhenUserIdLockedOut()
            throws Json.JsonException {
        String email = "joe.bloggs+4@digital.cabinet-office.gov.uk";
        String password = "password-1";
        userStore.signUp(email, "wrong-password");
        var sessionId = IdGenerator.generate();
        redis.createSession(sessionId);
        authSessionExtension.addSession(sessionId);
        authSessionExtension.addEmailToSession(sessionId, email);
        authSessionExtension.addClientIdToSession(sessionId, CLIENT_ID);
        var headers = validHeadersWithSessionId(sessionId);

        redis.createClientSession(
                CLIENT_SESSION_ID, CLIENT_NAME, basicAuthRequestBuilder.build().toParameters());

        var request = new LoginRequest(email, password, JourneyType.SIGN_IN);

        for (int i = 0; i < 5; i++) {
            var response = makeRequest(Optional.of(request), headers, Map.of());
            assertThat(response, hasStatus(401));
        }

        var response = makeRequest(Optional.of(request), headers, Map.of());
        assertThat(response, hasStatus(400));

        assertTxmaAuditEventsReceived(
                txmaAuditQueue,
                List.of(
                        AUTH_ACCOUNT_TEMPORARILY_LOCKED,
                        AUTH_ACCOUNT_TEMPORARILY_LOCKED,
                        AUTH_INVALID_CREDENTIALS,
                        AUTH_INVALID_CREDENTIALS,
                        AUTH_INVALID_CREDENTIALS,
                        AUTH_INVALID_CREDENTIALS,
                        AUTH_INVALID_CREDENTIALS));
    }

    private Map<String, String> validHeadersWithSessionId(String sessionId) {
        return Map.ofEntries(
                Map.entry("Session-Id", sessionId),
                Map.entry("X-API-Key", FRONTEND_API_KEY),
                Map.entry("Client-Session-Id", CLIENT_SESSION_ID),
                Map.entry(TXMA_AUDIT_ENCODED_HEADER, ENCODED_DEVICE_INFORMATION));
    }
}

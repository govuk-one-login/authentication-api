package uk.gov.di.authentication.api;

import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.frontendapi.entity.LoginRequest;
import uk.gov.di.authentication.frontendapi.entity.LoginResponse;
import uk.gov.di.authentication.frontendapi.lambda.LoginHandler;
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.MFAMethodType;
import uk.gov.di.authentication.shared.entity.ServiceType;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;

import java.net.URI;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Stream;

import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.ACCOUNT_TEMPORARILY_LOCKED;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.INVALID_CREDENTIALS;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.LOG_IN_SUCCESS;
import static uk.gov.di.authentication.shared.entity.CredentialTrustLevel.LOW_LEVEL;
import static uk.gov.di.authentication.shared.entity.CredentialTrustLevel.MEDIUM_LEVEL;
import static uk.gov.di.authentication.shared.entity.MFAMethodType.AUTH_APP;
import static uk.gov.di.authentication.shared.entity.MFAMethodType.NONE;
import static uk.gov.di.authentication.shared.entity.MFAMethodType.SMS;
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

    @BeforeEach
    void setup() {
        handler = new LoginHandler(TXMA_ENABLED_CONFIGURATION_SERVICE);
        txmaAuditQueue.clear();
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
        var sessionId = redis.createUnauthenticatedSessionWithEmail(email);
        var scope = new Scope(OIDCScopeValue.OPENID);

        userStore.signUp(email, password);
        userStore.updateTermsAndConditions(email, termsAndConditionsVersion);
        if (mfaMethodType.equals(SMS)) {
            userStore.setPhoneNumberAndVerificationStatus(
                    email, "01234567890", mfaMethodVerified, mfaMethodVerified);
        } else {
            userStore.updateMFAMethod(
                    email, mfaMethodType, mfaMethodVerified, true, "auth-app-credential");
        }

        AuthenticationRequest.Builder builder =
                new AuthenticationRequest.Builder(
                                ResponseType.CODE,
                                scope,
                                new ClientID(CLIENT_ID),
                                URI.create(REDIRECT_URI))
                        .nonce(new Nonce());
        if (level != null) {
            builder.customParameter("vtr", jsonArrayOf(level.getValue()));
        }
        redis.createClientSession(CLIENT_SESSION_ID, CLIENT_NAME, builder.build().toParameters());
        clientStore.registerClient(
                CLIENT_ID,
                "The test client",
                singletonList(REDIRECT_URI),
                singletonList("test-client@test.com"),
                singletonList(scope.toString()),
                Base64.getMimeEncoder()
                        .encodeToString(GENERATE_RSA_KEY_PAIR().getPublic().getEncoded()),
                singletonList("http://localhost/post-redirect-logout"),
                "http://example.com",
                String.valueOf(ServiceType.MANDATORY),
                "https://test.com",
                "public",
                true);

        Map<String, String> headers = new HashMap<>();
        headers.put("Session-Id", sessionId);
        headers.put("X-API-Key", FRONTEND_API_KEY);
        headers.put("Client-Session-Id", CLIENT_SESSION_ID);

        var response =
                makeRequest(
                        Optional.of(new LoginRequest(email, password, JourneyType.SIGN_IN)),
                        headers,
                        Map.of());
        assertThat(response, hasStatus(200));

        var loginResponse = objectMapper.readValue(response.getBody(), LoginResponse.class);

        assertThat(loginResponse.isMfaRequired(), equalTo(level != LOW_LEVEL));
        assertThat(
                loginResponse.getLatestTermsAndConditionsAccepted(),
                equalTo(termsAndConditionsVersion.equals(CURRENT_TERMS_AND_CONDITIONS)));

        var expectedMfaType =
                (mfaMethodType.equals(SMS) && !mfaMethodVerified) ? NONE : mfaMethodType;
        assertThat(loginResponse.getMfaMethodType(), equalTo(expectedMfaType));
        assertThat(loginResponse.isMfaMethodVerified(), equalTo(mfaMethodVerified));
        assertTrue(
                Objects.nonNull(redis.getSession(sessionId).getInternalCommonSubjectIdentifier()));
        assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(LOG_IN_SUCCESS));
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

    @Test
    void shouldCallLoginEndpointAndReturn401henUserHasInvalidCredentials()
            throws Json.JsonException {
        String email = "joe.bloggs+4@digital.cabinet-office.gov.uk";
        String password = "password-1";
        userStore.signUp(email, "wrong-password");
        String sessionId = redis.createUnauthenticatedSessionWithEmail(email);
        Map<String, String> headers = new HashMap<>();
        headers.put("Session-Id", sessionId);
        headers.put("X-API-Key", FRONTEND_API_KEY);

        var response =
                makeRequest(
                        Optional.of(new LoginRequest(email, password, JourneyType.SIGN_IN)),
                        headers,
                        Map.of());
        assertThat(response, hasStatus(401));
        assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(INVALID_CREDENTIALS));
    }

    @Test
    void shouldCallLoginEndpoint6TimesAndReturn400WhenUserIdLockedOut() throws Json.JsonException {
        String email = "joe.bloggs+4@digital.cabinet-office.gov.uk";
        String password = "password-1";
        userStore.signUp(email, "wrong-password");
        String sessionId = redis.createUnauthenticatedSessionWithEmail(email);
        Map<String, String> headers = new HashMap<>();
        headers.put("Session-Id", sessionId);
        headers.put("X-API-Key", FRONTEND_API_KEY);

        var response1 =
                makeRequest(
                        Optional.of(new LoginRequest(email, password, JourneyType.SIGN_IN)),
                        headers,
                        Map.of());
        assertThat(response1, hasStatus(401));
        var response2 =
                makeRequest(
                        Optional.of(new LoginRequest(email, password, JourneyType.SIGN_IN)),
                        headers,
                        Map.of());
        assertThat(response2, hasStatus(401));
        var response3 =
                makeRequest(
                        Optional.of(new LoginRequest(email, password, JourneyType.SIGN_IN)),
                        headers,
                        Map.of());
        assertThat(response3, hasStatus(401));
        var response4 =
                makeRequest(
                        Optional.of(new LoginRequest(email, password, JourneyType.SIGN_IN)),
                        headers,
                        Map.of());
        assertThat(response4, hasStatus(401));
        var response5 =
                makeRequest(
                        Optional.of(new LoginRequest(email, password, JourneyType.SIGN_IN)),
                        headers,
                        Map.of());
        assertThat(response5, hasStatus(401));
        var response6 =
                makeRequest(
                        Optional.of(new LoginRequest(email, password, JourneyType.SIGN_IN)),
                        headers,
                        Map.of());
        assertThat(response6, hasStatus(400));
        assertTxmaAuditEventsReceived(
                txmaAuditQueue,
                List.of(
                        ACCOUNT_TEMPORARILY_LOCKED,
                        INVALID_CREDENTIALS,
                        INVALID_CREDENTIALS,
                        INVALID_CREDENTIALS,
                        INVALID_CREDENTIALS,
                        INVALID_CREDENTIALS,
                        INVALID_CREDENTIALS));
    }

    @Test
    void shouldCallLoginEndpoint6TimesAndReturn400TwiceWhenUserIdLockedOut()
            throws Json.JsonException {
        String email = "joe.bloggs+4@digital.cabinet-office.gov.uk";
        String password = "password-1";
        userStore.signUp(email, "wrong-password");
        String sessionId = redis.createUnauthenticatedSessionWithEmail(email);
        Map<String, String> headers = new HashMap<>();
        headers.put("Session-Id", sessionId);
        headers.put("X-API-Key", FRONTEND_API_KEY);

        var response1 =
                makeRequest(
                        Optional.of(new LoginRequest(email, password, JourneyType.SIGN_IN)),
                        headers,
                        Map.of());
        assertThat(response1, hasStatus(401));
        var response2 =
                makeRequest(
                        Optional.of(new LoginRequest(email, password, JourneyType.SIGN_IN)),
                        headers,
                        Map.of());
        assertThat(response2, hasStatus(401));
        var response3 =
                makeRequest(
                        Optional.of(new LoginRequest(email, password, JourneyType.SIGN_IN)),
                        headers,
                        Map.of());
        assertThat(response3, hasStatus(401));
        var response4 =
                makeRequest(
                        Optional.of(new LoginRequest(email, password, JourneyType.SIGN_IN)),
                        headers,
                        Map.of());
        assertThat(response4, hasStatus(401));
        var response5 =
                makeRequest(
                        Optional.of(new LoginRequest(email, password, JourneyType.SIGN_IN)),
                        headers,
                        Map.of());
        assertThat(response5, hasStatus(401));
        var response6 =
                makeRequest(
                        Optional.of(new LoginRequest(email, password, JourneyType.SIGN_IN)),
                        headers,
                        Map.of());
        assertThat(response6, hasStatus(400));
        assertTxmaAuditEventsReceived(
                txmaAuditQueue,
                List.of(
                        ACCOUNT_TEMPORARILY_LOCKED,
                        ACCOUNT_TEMPORARILY_LOCKED,
                        INVALID_CREDENTIALS,
                        INVALID_CREDENTIALS,
                        INVALID_CREDENTIALS,
                        INVALID_CREDENTIALS,
                        INVALID_CREDENTIALS));
    }
}

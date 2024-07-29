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
import static uk.gov.di.authentication.shared.lambda.BaseFrontendHandler.TXMA_AUDIT_ENCODED_HEADER;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertTxmaAuditEventsReceived;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.*;
import static uk.gov.di.authentication.sharedtest.helper.JsonArrayHelper.jsonArrayOf;
import static uk.gov.di.authentication.sharedtest.helper.KeyPairHelper.GENERATE_RSA_KEY_PAIR;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class LoginIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String REDIRECT_URI = "http://localhost/redirect";
    private static final String CURRENT_TERMS_AND_CONDITIONS = "1.0";
    private static final String OLD_TERMS_AND_CONDITIONS = "0.1";

    @BeforeEach
    void setup() {
        handler = new LoginHandler(TXMA_ENABLED_CONFIGURATION_SERVICE, redisConnectionService);
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
        var sessionId = redis.createUnauthenticatedSessionWithEmail(EMAIL);
        var scope = new Scope(OIDCScopeValue.OPENID);

        userStore.signUp(EMAIL, PASSWORD);
        userStore.updateTermsAndConditions(EMAIL, termsAndConditionsVersion);
        if (mfaMethodType.equals(SMS)) {
            userStore.setPhoneNumberAndVerificationStatus(
                    EMAIL, UK_LANDLINE_NUMBER_NO_CC, mfaMethodVerified, mfaMethodVerified);
        } else {
            userStore.updateMFAMethod(
                    EMAIL, mfaMethodType, mfaMethodVerified, true, "auth-app-credential");
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
                singletonList(CLIENT_EMAIL),
                singletonList(scope.toString()),
                Base64.getMimeEncoder()
                        .encodeToString(GENERATE_RSA_KEY_PAIR().getPublic().getEncoded()),
                singletonList("http://localhost/post-redirect-logout"),
                "http://example.com",
                String.valueOf(ServiceType.MANDATORY),
                "https://test.com",
                "public");

        Map<String, String> headers = new HashMap<>();
        headers.put("Session-Id", sessionId);
        headers.put("X-API-Key", FRONTEND_API_KEY);
        headers.put("Client-Session-Id", CLIENT_SESSION_ID);
        headers.put(TXMA_AUDIT_ENCODED_HEADER, ENCODED_DEVICE_DETAILS);

        var response =
                makeRequest(
                        Optional.of(new LoginRequest(EMAIL, PASSWORD, JourneyType.SIGN_IN)),
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
        userStore.signUp(email, PASSWORD_BAD);
        String sessionId = redis.createUnauthenticatedSessionWithEmail(email);
        Map<String, String> headers = new HashMap<>();
        headers.put("Session-Id", sessionId);
        headers.put("X-API-Key", FRONTEND_API_KEY);
        headers.put(TXMA_AUDIT_ENCODED_HEADER, ENCODED_DEVICE_DETAILS);

        var response =
                makeRequest(
                        Optional.of(new LoginRequest(email, PASSWORD, JourneyType.SIGN_IN)),
                        headers,
                        Map.of());
        assertThat(response, hasStatus(401));
        assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(INVALID_CREDENTIALS));
    }

    @Test
    void shouldCallLoginEndpoint6TimesAndReturn400WhenUserIdLockedOut() throws Json.JsonException {
        String email = buildTestEmail(4);
        userStore.signUp(email, PASSWORD_BAD);
        String sessionId = redis.createUnauthenticatedSessionWithEmail(email);
        Map<String, String> headers = new HashMap<>();
        headers.put("Session-Id", sessionId);
        headers.put("X-API-Key", FRONTEND_API_KEY);
        headers.put(TXMA_AUDIT_ENCODED_HEADER, ENCODED_DEVICE_DETAILS);

        var request = new LoginRequest(email, PASSWORD, JourneyType.SIGN_IN);

        for (int i = 0; i < 5; i++) {
            var response = makeRequest(Optional.of(request), headers, Map.of());
            assertThat(response, hasStatus(401));
        }

        var response = makeRequest(Optional.of(request), headers, Map.of());
        assertThat(response, hasStatus(400));

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
        String email = buildTestEmail(4);
        userStore.signUp(email, PASSWORD_BAD);
        String sessionId = redis.createUnauthenticatedSessionWithEmail(email);
        Map<String, String> headers = new HashMap<>();
        headers.put("Session-Id", sessionId);
        headers.put("X-API-Key", FRONTEND_API_KEY);
        headers.put(TXMA_AUDIT_ENCODED_HEADER, ENCODED_DEVICE_DETAILS);

        var request = new LoginRequest(email, PASSWORD, JourneyType.SIGN_IN);

        for (int i = 0; i < 5; i++) {
            var response = makeRequest(Optional.of(request), headers, Map.of());
            assertThat(response, hasStatus(401));
        }

        var response = makeRequest(Optional.of(request), headers, Map.of());
        assertThat(response, hasStatus(400));

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

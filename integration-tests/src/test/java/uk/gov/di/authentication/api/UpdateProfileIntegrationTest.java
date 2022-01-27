package uk.gov.di.authentication.api;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.frontendapi.entity.UpdateProfileRequest;
import uk.gov.di.authentication.frontendapi.lambda.UpdateProfileHandler;
import uk.gov.di.authentication.shared.entity.BaseAPIResponse;
import uk.gov.di.authentication.shared.entity.ClientConsent;
import uk.gov.di.authentication.shared.entity.ServiceType;
import uk.gov.di.authentication.shared.entity.SessionState;
import uk.gov.di.authentication.shared.entity.ValidScopes;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;

import java.io.IOException;
import java.net.URI;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.UPDATE_PROFILE_REQUEST_RECEIVED;
import static uk.gov.di.authentication.frontendapi.entity.UpdateProfileType.ADD_PHONE_NUMBER;
import static uk.gov.di.authentication.frontendapi.entity.UpdateProfileType.CAPTURE_CONSENT;
import static uk.gov.di.authentication.frontendapi.entity.UpdateProfileType.UPDATE_TERMS_CONDS;
import static uk.gov.di.authentication.shared.entity.SessionState.ADDED_UNVERIFIED_PHONE_NUMBER;
import static uk.gov.di.authentication.shared.entity.SessionState.CONSENT_ADDED;
import static uk.gov.di.authentication.shared.entity.SessionState.UPDATED_TERMS_AND_CONDITIONS_ACCEPTED;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertEventTypesReceived;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class UpdateProfileIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String EMAIL_ADDRESS = "test@test.com";
    private static final String CLIENT_ID = "test-id";

    @BeforeEach
    void setup() {
        handler = new UpdateProfileHandler(TEST_CONFIGURATION_SERVICE);
    }

    @Test
    public void shouldCallUpdateProfileEndpointToUpdatePhoneNumberAndReturn200()
            throws IOException {
        String sessionId = redis.createSession();
        String clientSessionId = IdGenerator.generate();
        setUpTest(sessionId, clientSessionId, SessionState.TWO_FACTOR_REQUIRED);
        UpdateProfileRequest request =
                new UpdateProfileRequest(EMAIL_ADDRESS, ADD_PHONE_NUMBER, "07123456789");

        var response =
                makeRequest(
                        Optional.of(request),
                        constructFrontendHeaders(sessionId, clientSessionId),
                        Map.of());

        assertThat(response, hasStatus(200));
        BaseAPIResponse baseAPIResponse =
                objectMapper.readValue(response.getBody(), BaseAPIResponse.class);
        assertThat(baseAPIResponse.getSessionState(), equalTo(ADDED_UNVERIFIED_PHONE_NUMBER));

        assertEventTypesReceived(
                auditTopic,
                List.of(UPDATE_PROFILE_REQUEST_RECEIVED, UPDATE_PROFILE_REQUEST_RECEIVED));
    }

    @Test
    public void shouldCallUpdateProfileToUpdateConsentAndReturn200() throws IOException {
        String sessionId = redis.createSession();
        String clientSessionId = IdGenerator.generate();
        AuthenticationRequest authRequest =
                setUpTest(sessionId, clientSessionId, SessionState.CONSENT_REQUIRED);
        redis.createClientSession(clientSessionId, authRequest.toParameters());
        UpdateProfileRequest request =
                new UpdateProfileRequest(EMAIL_ADDRESS, CAPTURE_CONSENT, String.valueOf(true));

        var response =
                makeRequest(
                        Optional.of(request),
                        constructFrontendHeaders(sessionId, clientSessionId),
                        Map.of());

        assertThat(response, hasStatus(200));
        Optional<ClientConsent> consent =
                userStore
                        .getUserConsents(EMAIL_ADDRESS)
                        .flatMap(
                                list ->
                                        list.stream()
                                                .filter(c -> c.getClientId().equals(CLIENT_ID))
                                                .findFirst());
        assertTrue(consent.get().getClaims().containsAll(OIDCScopeValue.OPENID.getClaimNames()));
        assertTrue(consent.get().getClaims().containsAll(OIDCScopeValue.EMAIL.getClaimNames()));
        BaseAPIResponse baseAPIResponse =
                objectMapper.readValue(response.getBody(), BaseAPIResponse.class);
        assertThat(baseAPIResponse.getSessionState(), equalTo(CONSENT_ADDED));

        assertEventTypesReceived(
                auditTopic,
                List.of(UPDATE_PROFILE_REQUEST_RECEIVED, UPDATE_PROFILE_REQUEST_RECEIVED));
    }

    @Test
    public void shouldCallUpdateProfileToApproveTermsAndConditonsAndReturn200() throws IOException {
        String sessionId = redis.createSession();
        String clientSessionId = IdGenerator.generate();
        setUpTest(sessionId, clientSessionId, SessionState.UPDATED_TERMS_AND_CONDITIONS);

        UpdateProfileRequest request =
                new UpdateProfileRequest(EMAIL_ADDRESS, UPDATE_TERMS_CONDS, String.valueOf(true));

        var response =
                makeRequest(
                        Optional.of(request),
                        constructFrontendHeaders(sessionId, clientSessionId),
                        Map.of());

        assertThat(response, hasStatus(200));
        BaseAPIResponse baseAPIResponse =
                objectMapper.readValue(response.getBody(), BaseAPIResponse.class);
        assertThat(
                baseAPIResponse.getSessionState(), equalTo(UPDATED_TERMS_AND_CONDITIONS_ACCEPTED));

        assertEventTypesReceived(
                auditTopic,
                List.of(UPDATE_PROFILE_REQUEST_RECEIVED, UPDATE_PROFILE_REQUEST_RECEIVED));
    }

    private AuthenticationRequest setUpTest(
            String sessionId, String clientSessionId, SessionState sessionState)
            throws JsonProcessingException {
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        scope.add(OIDCScopeValue.EMAIL);
        redis.addEmailToSession(sessionId, EMAIL_ADDRESS);
        redis.setSessionState(sessionId, sessionState);
        AuthenticationRequest authRequest =
                new AuthenticationRequest.Builder(
                                ResponseType.CODE,
                                scope,
                                new ClientID(CLIENT_ID),
                                URI.create("http://localhost/redirect"))
                        .nonce(new Nonce())
                        .build();
        redis.createClientSession(clientSessionId, authRequest.toParameters());
        clientStore.registerClient(
                CLIENT_ID,
                "test-client",
                singletonList("redirect-url"),
                singletonList(EMAIL_ADDRESS),
                List.of("openid", "email"),
                "public-key",
                singletonList("http://localhost/post-redirect-logout"),
                String.valueOf(ServiceType.MANDATORY),
                "https://test.com",
                "public",
                true);
        Set<String> claims = ValidScopes.getClaimsForListOfScopes(scope.toStringList());
        userStore.signUp(EMAIL_ADDRESS, "password");
        userStore.updateConsent(
                EMAIL_ADDRESS,
                new ClientConsent(
                        CLIENT_ID, claims, LocalDateTime.now(ZoneId.of("UTC")).toString()));
        return authRequest;
    }
}

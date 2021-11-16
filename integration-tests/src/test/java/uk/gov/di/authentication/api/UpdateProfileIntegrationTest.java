package uk.gov.di.authentication.api;

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
import uk.gov.di.authentication.helpers.DynamoHelper;
import uk.gov.di.authentication.helpers.RedisHelper;
import uk.gov.di.authentication.shared.entity.BaseAPIResponse;
import uk.gov.di.authentication.shared.entity.ClientConsent;
import uk.gov.di.authentication.shared.entity.ServiceType;
import uk.gov.di.authentication.shared.entity.SessionState;
import uk.gov.di.authentication.shared.entity.ValidScopes;
import uk.gov.di.authentication.shared.helpers.IdGenerator;

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
import static uk.gov.di.authentication.frontendapi.entity.UpdateProfileType.ADD_PHONE_NUMBER;
import static uk.gov.di.authentication.frontendapi.entity.UpdateProfileType.CAPTURE_CONSENT;
import static uk.gov.di.authentication.frontendapi.entity.UpdateProfileType.UPDATE_TERMS_CONDS;
import static uk.gov.di.authentication.shared.entity.SessionState.ADDED_UNVERIFIED_PHONE_NUMBER;
import static uk.gov.di.authentication.shared.entity.SessionState.CONSENT_ADDED;
import static uk.gov.di.authentication.shared.entity.SessionState.UPDATED_TERMS_AND_CONDITIONS_ACCEPTED;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class UpdateProfileIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String EMAIL_ADDRESS = "test@test.com";
    private static final String CLIENT_ID = "test-id";

    @BeforeEach
    void setup() {
        handler = new UpdateProfileHandler(configurationService);
    }

    @Test
    public void shouldCallUpdateProfileEndpointToUpdatePhoneNumberAndReturn200()
            throws IOException {
        String sessionId = RedisHelper.createSession();
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
    }

    @Test
    public void shouldCallUpdateProfileToUpdateConsentAndReturn200() throws IOException {
        String sessionId = RedisHelper.createSession();
        String clientSessionId = IdGenerator.generate();
        AuthenticationRequest authRequest =
                setUpTest(sessionId, clientSessionId, SessionState.CONSENT_REQUIRED);
        RedisHelper.createClientSession(clientSessionId, authRequest.toParameters());
        UpdateProfileRequest request =
                new UpdateProfileRequest(EMAIL_ADDRESS, CAPTURE_CONSENT, String.valueOf(true));

        var response =
                makeRequest(
                        Optional.of(request),
                        constructFrontendHeaders(sessionId, clientSessionId),
                        Map.of());

        assertThat(response, hasStatus(200));
        Optional<ClientConsent> consent =
                DynamoHelper.getUserConsents(EMAIL_ADDRESS)
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
    }

    @Test
    public void shouldCallUpdateProfileToApproveTermsAndConditonsAndReturn200() throws IOException {
        String sessionId = RedisHelper.createSession();
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
    }

    private AuthenticationRequest setUpTest(
            String sessionId, String clientSessionId, SessionState sessionState) {
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        scope.add(OIDCScopeValue.EMAIL);
        RedisHelper.addEmailToSession(sessionId, EMAIL_ADDRESS);
        RedisHelper.setSessionState(sessionId, sessionState);
        AuthenticationRequest authRequest =
                new AuthenticationRequest.Builder(
                                ResponseType.CODE,
                                scope,
                                new ClientID(CLIENT_ID),
                                URI.create("http://localhost/redirect"))
                        .nonce(new Nonce())
                        .build();
        RedisHelper.createClientSession(clientSessionId, authRequest.toParameters());
        DynamoHelper.registerClient(
                CLIENT_ID,
                "test-client",
                singletonList("redirect-url"),
                singletonList(EMAIL_ADDRESS),
                List.of("openid", "email"),
                "public-key",
                singletonList("http://localhost/post-redirect-logout"),
                String.valueOf(ServiceType.MANDATORY),
                "https://test.com",
                "public");
        Set<String> claims = ValidScopes.getClaimsForListOfScopes(scope.toStringList());
        DynamoHelper.signUp(EMAIL_ADDRESS, "password");
        DynamoHelper.updateConsent(
                EMAIL_ADDRESS,
                new ClientConsent(
                        CLIENT_ID, claims, LocalDateTime.now(ZoneId.of("UTC")).toString()));
        return authRequest;
    }
}

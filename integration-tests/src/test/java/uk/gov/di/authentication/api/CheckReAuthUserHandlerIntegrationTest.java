package uk.gov.di.authentication.api;

import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.frontendapi.entity.CheckReauthUserRequest;
import uk.gov.di.authentication.frontendapi.lambda.CheckReAuthUserHandler;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.helper.CommonTestVariables;
import uk.gov.di.orchestration.shared.entity.ErrorResponse;
import uk.gov.di.orchestration.sharedtest.helper.KeyPairHelper;

import java.net.URI;
import java.security.KeyPair;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static uk.gov.di.authentication.shared.lambda.BaseFrontendHandler.TXMA_AUDIT_ENCODED_HEADER;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.*;
import static uk.gov.di.orchestration.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.orchestration.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class CheckReAuthUserHandlerIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String INTERNAl_SECTOR_HOST = "test.account.gov.uk";
    private static final String CLIENT_SESSION_ID = "a-client-session-id";
    private static final ClientID CLIENT_ID = new ClientID(CommonTestVariables.CLIENT_ID);
    private static final Subject SUBJECT = new Subject();
    private final KeyPair keyPair = KeyPairHelper.GENERATE_RSA_KEY_PAIR();
    private static final URI REDIRECT_URI =
            URI.create(System.getenv("STUB_RELYING_PARTY_REDIRECT_URI"));
    private Map<String, String> headers;

    @BeforeEach
    void setup() throws Json.JsonException {
        var sessionId = redis.createAuthenticatedSessionWithEmail(EMAIL);
        headers = createHeaders(sessionId);
        redis.createClientSession(CLIENT_SESSION_ID, createClientSession());
        handler =
                new CheckReAuthUserHandler(
                        TXMA_ENABLED_CONFIGURATION_SERVICE, redisConnectionService);
        txmaAuditQueue.clear();
    }

    @Test
    void shouldReturn200WithSuccessfulCheckReAuthUserRequest() {
        userStore.signUp(EMAIL, PASSWORD, SUBJECT);
        registerClient("https://" + INTERNAl_SECTOR_HOST);
        byte[] salt = userStore.addSalt(EMAIL);
        var expectedPairwiseId =
                ClientSubjectHelper.calculatePairwiseIdentifier(
                        SUBJECT.getValue(), INTERNAl_SECTOR_HOST, salt);
        var request = new CheckReauthUserRequest(EMAIL, expectedPairwiseId);
        var response =
                makeRequest(
                        Optional.of(request),
                        headers,
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of("principalId", expectedPairwiseId));

        assertThat(response, hasStatus(200));
    }

    @Test
    void shouldReturn404WhenUserNotFound() {
        var request = new CheckReauthUserRequest(EMAIL, "random-pairwise-id");
        var response =
                makeRequest(
                        Optional.of(request),
                        headers,
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of());

        assertThat(response, hasStatus(404));
    }

    @Test
    void shouldReturn404WhenUserNotMatched() {
        userStore.signUp(EMAIL, PASSWORD, SUBJECT);
        registerClient("https://randomSectorIDuRI.COM");
        byte[] salt = userStore.addSalt(EMAIL);
        var expectedPairwiseId =
                ClientSubjectHelper.calculatePairwiseIdentifier(
                        SUBJECT.getValue(), INTERNAl_SECTOR_HOST, salt);
        var request = new CheckReauthUserRequest(EMAIL, expectedPairwiseId);
        var response =
                makeRequest(
                        Optional.of(request),
                        headers,
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of("principalId", expectedPairwiseId));

        assertThat(response, hasStatus(404));
    }

    @Test
    void shouldReturn400WhenUserEnteredInvalidEmailTooManyTimes() {
        userStore.signUp(EMAIL, PASSWORD, SUBJECT);
        registerClient("https://randomSectorIDuRI.COM");

        redis.incrementEmailCount(EMAIL);
        redis.incrementEmailCount(EMAIL);
        redis.incrementEmailCount(EMAIL);
        redis.incrementEmailCount(EMAIL);
        redis.incrementEmailCount(EMAIL);

        byte[] salt = userStore.addSalt(EMAIL);
        var expectedPairwiseId =
                ClientSubjectHelper.calculatePairwiseIdentifier(
                        SUBJECT.getValue(), INTERNAl_SECTOR_HOST, salt);
        var request = new CheckReauthUserRequest(EMAIL, expectedPairwiseId);
        var response =
                makeRequest(
                        Optional.of(request),
                        headers,
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of("principalId", expectedPairwiseId));

        assertThat(response, hasStatus(400));
    }

    @Test
    void shouldReturn400WhenUserHasBeenBlockedForMaxPasswordRetries() {
        userStore.signUp(EMAIL, PASSWORD, SUBJECT);
        registerClient("https://randomSectorIDuRI.COM");

        redis.incrementPasswordCountReauthJourney(EMAIL);
        redis.incrementPasswordCountReauthJourney(EMAIL);
        redis.incrementPasswordCountReauthJourney(EMAIL);
        redis.incrementPasswordCountReauthJourney(EMAIL);
        redis.incrementPasswordCountReauthJourney(EMAIL);
        redis.incrementPasswordCountReauthJourney(EMAIL);

        byte[] salt = userStore.addSalt(EMAIL);
        var expectedPairwiseId =
                ClientSubjectHelper.calculatePairwiseIdentifier(
                        SUBJECT.getValue(), INTERNAl_SECTOR_HOST, salt);
        var request = new CheckReauthUserRequest(EMAIL, expectedPairwiseId);
        var response =
                makeRequest(
                        Optional.of(request),
                        headers,
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of("principalId", expectedPairwiseId));

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1045));
    }

    @Test
    void shouldReturn400WhenUserProfileNotFoundAndHasEnteredInvalidEmailTooManyTimes() {
        userStore.signUp(EMAIL, PASSWORD, SUBJECT);
        registerClient("https://" + INTERNAl_SECTOR_HOST);

        var randomEmail = "random_email@email.com";

        redis.incrementEmailCount(EMAIL);
        redis.incrementEmailCount(EMAIL);
        redis.incrementEmailCount(EMAIL);
        redis.incrementEmailCount(EMAIL);
        redis.incrementEmailCount(EMAIL);

        var request = new CheckReauthUserRequest(randomEmail, "random-pairwise-id");

        var response =
                makeRequest(
                        Optional.of(request),
                        headers,
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of());

        assertThat(response, hasStatus(400));
    }

    private ClientSession createClientSession() {
        var authRequestBuilder =
                new AuthenticationRequest.Builder(
                                ResponseType.CODE,
                                new Scope(OIDCScopeValue.OPENID),
                                new ClientID(CLIENT_ID),
                                URI.create("http://localhost/redirect"))
                        .state(new State())
                        .nonce(new Nonce());
        return new ClientSession(
                authRequestBuilder.build().toParameters(),
                LocalDateTime.now(),
                VectorOfTrust.getDefaults(),
                CLIENT_NAME);
    }

    private void registerClient(String sectorIdentifierUri) {
        clientStore.registerClient(
                CLIENT_ID.getValue(),
                CLIENT_NAME,
                singletonList(REDIRECT_URI.toString()),
                singletonList(EMAIL),
                new Scope(OIDCScopeValue.OPENID).toStringList(),
                Base64.getMimeEncoder().encodeToString(keyPair.getPublic().getEncoded()),
                singletonList("http://localhost/post-redirect-logout"),
                "http://example.com",
                String.valueOf(uk.gov.di.orchestration.shared.entity.ServiceType.MANDATORY),
                sectorIdentifierUri,
                "pairwise");
    }

    private Map<String, String> createHeaders(String sessionId) {
        Map<String, String> headers = new HashMap<>();
        headers.put("Session-Id", sessionId);
        headers.put("X-API-Key", FRONTEND_API_KEY);
        headers.put("Client-Session-Id", CLIENT_SESSION_ID);
        headers.put(TXMA_AUDIT_ENCODED_HEADER, ENCODED_DEVICE_DETAILS);
        return headers;
    }
}

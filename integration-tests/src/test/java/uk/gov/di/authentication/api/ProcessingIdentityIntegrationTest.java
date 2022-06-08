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
import uk.gov.di.authentication.ipv.entity.ProcessingIdentityResponse;
import uk.gov.di.authentication.ipv.entity.ProcessingIdentityStatus;
import uk.gov.di.authentication.ipv.lambda.ProcessingIdentityHandler;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.ClientType;
import uk.gov.di.authentication.shared.entity.ServiceType;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.helper.SignedCredentialHelper;

import java.net.URI;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static java.util.Collections.emptyMap;
import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static uk.gov.di.authentication.api.AuthorisationIntegrationTest.configurationService;
import static uk.gov.di.authentication.shared.helpers.ClientSubjectHelper.calculatePairwiseIdentifier;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class ProcessingIdentityIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    public static final String SESSION_ID = "some-session-id";
    public static final String CLIENT_SESSION_ID = "some-client-session-id";
    private static final ClientID CLIENT_ID = new ClientID("test-client");
    private static final String CLIENT_SECTOR = "https://test.com";
    private static final Subject INTERNAL_SUBJECT = new Subject();
    private static final String TEST_EMAIL_ADDRESS = "test@emailtest.com";
    public static final Scope SCOPE = new Scope(OIDCScopeValue.OPENID);
    public static final State STATE = new State();

    @BeforeEach
    void setup() {
        handler = new ProcessingIdentityHandler(configurationService);
    }

    @Test
    void shouldReturnStatusOfCOMPLETEDWhenEntryInDatabaseAndJWTIsPresent()
            throws Json.JsonException {
        setupSession();
        setupClient();
        byte[] salt = setupUser();
        var signedCredential = SignedCredentialHelper.generateCredential();
        var pairwiseIdentifier =
                calculatePairwiseIdentifier(INTERNAL_SUBJECT.getValue(), "test.com", salt);
        identityStore.addCoreIdentityJWT(pairwiseIdentifier, signedCredential.serialize());

        Map<String, String> headers = new HashMap<>();
        headers.put("Session-Id", SESSION_ID);
        headers.put("Client-Session-Id", CLIENT_SESSION_ID);
        headers.put("X-API-Key", FRONTEND_API_KEY);

        var response =
                makeRequest(
                        Optional.of(format("{ \"email\": \"%s\"}", TEST_EMAIL_ADDRESS)),
                        headers,
                        Map.of());

        assertThat(response, hasStatus(200));
        assertThat(
                response,
                hasBody(
                        objectMapper.writeValueAsString(
                                new ProcessingIdentityResponse(
                                        ProcessingIdentityStatus.COMPLETED))));
    }

    @Test
    void shouldReturnStatusOfPROCESSINGWhenEntryInDatabaseButNoJWTIsPresent()
            throws Json.JsonException {
        setupSession();
        setupClient();
        byte[] salt = setupUser();
        var pairwiseIdentifier =
                calculatePairwiseIdentifier(INTERNAL_SUBJECT.getValue(), "test.com", salt);
        identityStore.addAdditionalClaims(pairwiseIdentifier, emptyMap());

        Map<String, String> headers = new HashMap<>();
        headers.put("Session-Id", SESSION_ID);
        headers.put("Client-Session-Id", CLIENT_SESSION_ID);
        headers.put("X-API-Key", FRONTEND_API_KEY);

        var response =
                makeRequest(
                        Optional.of(format("{ \"email\": \"%s\"}", TEST_EMAIL_ADDRESS)),
                        headers,
                        Map.of());

        assertThat(response, hasStatus(200));
        assertThat(
                response,
                hasBody(
                        objectMapper.writeValueAsString(
                                new ProcessingIdentityResponse(
                                        ProcessingIdentityStatus.PROCESSING))));
    }

    @Test
    void shouldReturnStatusOfERRORWhenEntryIsNotInDatabase() throws Json.JsonException {
        setupSession();
        setupClient();
        setupUser();

        Map<String, String> headers = new HashMap<>();
        headers.put("Session-Id", SESSION_ID);
        headers.put("Client-Session-Id", CLIENT_SESSION_ID);
        headers.put("X-API-Key", FRONTEND_API_KEY);

        var response =
                makeRequest(
                        Optional.of(format("{ \"email\": \"%s\"}", TEST_EMAIL_ADDRESS)),
                        headers,
                        Map.of());

        assertThat(response, hasStatus(200));
        assertThat(
                response,
                hasBody(
                        objectMapper.writeValueAsString(
                                new ProcessingIdentityResponse(ProcessingIdentityStatus.ERROR))));
    }

    private void setupSession() throws Json.JsonException {
        var authRequestBuilder =
                new AuthenticationRequest.Builder(
                                ResponseType.CODE,
                                SCOPE,
                                new ClientID(CLIENT_ID),
                                URI.create("http://localhost/redirect"))
                        .state(STATE)
                        .nonce(new Nonce());
        redis.createSession(SESSION_ID);
        var clientSession =
                new ClientSession(
                        authRequestBuilder.build().toParameters(),
                        LocalDateTime.now(),
                        VectorOfTrust.getDefaults());
        redis.createClientSession(CLIENT_SESSION_ID, clientSession);
        redis.addStateToRedis(STATE, SESSION_ID);
    }

    private void setupClient() {
        clientStore.registerClient(
                CLIENT_ID.getValue(),
                "test-client",
                singletonList(URI.create("http://localhost/redirect").toString()),
                singletonList(TEST_EMAIL_ADDRESS),
                singletonList("openid"),
                "",
                singletonList("http://localhost/post-redirect-logout"),
                "http://example.com",
                String.valueOf(ServiceType.MANDATORY),
                CLIENT_SECTOR,
                "pairwise",
                true,
                ClientType.WEB,
                true);
    }

    private byte[] setupUser() {
        userStore.signUp(TEST_EMAIL_ADDRESS, "password-1", INTERNAL_SUBJECT);
        return userStore.addSalt(TEST_EMAIL_ADDRESS);
    }
}

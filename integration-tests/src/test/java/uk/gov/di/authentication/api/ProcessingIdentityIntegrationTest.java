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
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.ipv.entity.ProcessingIdentityResponse;
import uk.gov.di.authentication.ipv.entity.ProcessingIdentityStatus;
import uk.gov.di.authentication.ipv.lambda.ProcessingIdentityHandler;
import uk.gov.di.orchestration.shared.entity.LevelOfConfidence;
import uk.gov.di.orchestration.shared.entity.OrchClientSessionItem;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem;
import uk.gov.di.orchestration.shared.entity.VectorOfTrust;
import uk.gov.di.orchestration.shared.helpers.SaltHelper;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.orchestration.sharedtest.extensions.OrchClientSessionExtension;
import uk.gov.di.orchestration.sharedtest.extensions.OrchSessionExtension;
import uk.gov.di.orchestration.sharedtest.helper.SignedCredentialHelper;

import java.net.URI;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static java.util.Collections.emptyMap;
import static org.hamcrest.MatcherAssert.assertThat;
import static uk.gov.di.authentication.ipv.domain.IPVAuditableEvent.PROCESSING_IDENTITY_REQUEST;
import static uk.gov.di.authentication.shared.helpers.TxmaAuditHelper.TXMA_AUDIT_ENCODED_HEADER;
import static uk.gov.di.orchestration.shared.helpers.ClientSubjectHelper.calculatePairwiseIdentifier;
import static uk.gov.di.orchestration.sharedtest.helper.AuditAssertionsHelper.assertTxmaAuditEventsReceived;
import static uk.gov.di.orchestration.sharedtest.helper.IdentityTestData.CORE_IDENTITY_CLAIM;
import static uk.gov.di.orchestration.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.orchestration.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class ProcessingIdentityIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    public static final String SESSION_ID = "some-session-id";
    public static final String CLIENT_SESSION_ID = "some-client-session-id";
    private static final ClientID CLIENT_ID = new ClientID("test-client");
    private static final String CLIENT_NAME = "client-name";
    private static final Subject INTERNAL_SUBJECT = new Subject();
    private static final String TEST_EMAIL_ADDRESS = "test@emailtest.com";
    public static final Scope SCOPE = new Scope(OIDCScopeValue.OPENID);
    public static final State STATE = new State();
    public static final String ENCODED_DEVICE_INFORMATION =
            "R21vLmd3QilNKHJsaGkvTFxhZDZrKF44SStoLFsieG0oSUY3aEhWRVtOMFRNMVw1dyInKzB8OVV5N09hOi8kLmlLcWJjJGQiK1NPUEJPPHBrYWJHP358NDg2ZDVc";
    private static final byte[] SALT = SaltHelper.generateNewSalt();

    @RegisterExtension
    protected static final OrchSessionExtension orchSessionExtension = new OrchSessionExtension();

    @RegisterExtension
    protected static final OrchClientSessionExtension orchClientSessionExtension =
            new OrchClientSessionExtension();

    @BeforeEach
    void setup() {
        clientStore.createClient().withClientId(CLIENT_ID.getValue()).saveToDynamo();
        handler = new ProcessingIdentityHandler(TXMA_AND_AIS_ENABLED_CONFIGURATION_SERVICE);
        txmaAuditQueue.clear();
    }

    @Test
    void shouldReturnStatusOfCOMPLETEDWhenEntryInDatabaseAndJWTIsPresent()
            throws Json.JsonException {
        setupSession(false);
        var signedCredential = SignedCredentialHelper.generateCredential();
        var pairwiseIdentifier =
                calculatePairwiseIdentifier(INTERNAL_SUBJECT.getValue(), "test.com", SALT);
        identityStore.addCoreIdentityJWT(
                CLIENT_SESSION_ID, pairwiseIdentifier, signedCredential.serialize());

        Map<String, String> headers = new HashMap<>();
        headers.put("Session-Id", SESSION_ID);
        headers.put("Client-Session-Id", CLIENT_SESSION_ID);
        headers.put("X-API-Key", FRONTEND_API_KEY);
        headers.put(TXMA_AUDIT_ENCODED_HEADER, ENCODED_DEVICE_INFORMATION);

        var response =
                makeRequest(
                        Optional.of(format("{ \"email\": \"%s\"}", TEST_EMAIL_ADDRESS)),
                        headers,
                        Map.of());

        assertThat(response, hasStatus(200));
        assertThat(
                response,
                hasJsonBody(new ProcessingIdentityResponse(ProcessingIdentityStatus.COMPLETED)));

        assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(PROCESSING_IDENTITY_REQUEST));
    }

    @Test
    void shouldReturnStatusOfPROCESSINGWhenEntryInDatabaseButNoJWTIsPresent()
            throws Json.JsonException {
        setupSession(false);
        var pairwiseIdentifier =
                calculatePairwiseIdentifier(INTERNAL_SUBJECT.getValue(), "test.com", SALT);
        identityStore.saveIdentityClaims(
                CLIENT_SESSION_ID,
                pairwiseIdentifier,
                emptyMap(),
                LevelOfConfidence.MEDIUM_LEVEL.getValue(),
                CORE_IDENTITY_CLAIM);

        Map<String, String> headers = new HashMap<>();
        headers.put("Session-Id", SESSION_ID);
        headers.put("Client-Session-Id", CLIENT_SESSION_ID);
        headers.put("X-API-Key", FRONTEND_API_KEY);
        headers.put(TXMA_AUDIT_ENCODED_HEADER, ENCODED_DEVICE_INFORMATION);

        var response =
                makeRequest(
                        Optional.of(format("{ \"email\": \"%s\"}", TEST_EMAIL_ADDRESS)),
                        headers,
                        Map.of());

        assertThat(response, hasStatus(200));
        assertThat(
                response,
                hasJsonBody(new ProcessingIdentityResponse(ProcessingIdentityStatus.PROCESSING)));

        assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(PROCESSING_IDENTITY_REQUEST));
    }

    @Test
    void shouldReturnStatusOfERRORWhenEntryIsNotInDatabaseOnSecondAttempt()
            throws Json.JsonException {
        setupSession(true);

        Map<String, String> headers = new HashMap<>();
        headers.put("Session-Id", SESSION_ID);
        headers.put("Client-Session-Id", CLIENT_SESSION_ID);
        headers.put("X-API-Key", FRONTEND_API_KEY);
        headers.put(TXMA_AUDIT_ENCODED_HEADER, ENCODED_DEVICE_INFORMATION);

        var response =
                makeRequest(
                        Optional.of(format("{ \"email\": \"%s\"}", TEST_EMAIL_ADDRESS)),
                        headers,
                        Map.of());

        assertThat(response, hasStatus(200));
        assertThat(
                response,
                hasJsonBody(new ProcessingIdentityResponse(ProcessingIdentityStatus.ERROR)));

        assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(PROCESSING_IDENTITY_REQUEST));
    }

    @Test
    void shouldReturnStatusOfNO_ENTRYWhenEntryIsNotInDatabaseOnFirstAttempt()
            throws Json.JsonException {
        setupSession(false);

        Map<String, String> headers = new HashMap<>();
        headers.put("Session-Id", SESSION_ID);
        headers.put("Client-Session-Id", CLIENT_SESSION_ID);
        headers.put("X-API-Key", FRONTEND_API_KEY);
        headers.put(TXMA_AUDIT_ENCODED_HEADER, ENCODED_DEVICE_INFORMATION);

        var response =
                makeRequest(
                        Optional.of(format("{ \"email\": \"%s\"}", TEST_EMAIL_ADDRESS)),
                        headers,
                        Map.of());

        assertThat(response, hasStatus(200));
        assertThat(
                response,
                hasJsonBody(new ProcessingIdentityResponse(ProcessingIdentityStatus.NO_ENTRY)));

        assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(PROCESSING_IDENTITY_REQUEST));
    }

    private void setupSession(boolean incrementProcessIdentityAttempts) throws Json.JsonException {
        var authRequestBuilder =
                new AuthenticationRequest.Builder(
                                ResponseType.CODE,
                                SCOPE,
                                new ClientID(CLIENT_ID),
                                URI.create("http://localhost/redirect"))
                        .state(STATE)
                        .nonce(new Nonce());
        orchSessionExtension.addSession(
                new OrchSessionItem(SESSION_ID)
                        .withInternalCommonSubjectId(INTERNAL_SUBJECT.getValue()));
        var creationDate = LocalDateTime.now();
        var orchClientSession =
                new OrchClientSessionItem(
                        CLIENT_SESSION_ID,
                        authRequestBuilder.build().toParameters(),
                        creationDate,
                        List.of(VectorOfTrust.getDefaults()),
                        CLIENT_NAME);
        orchClientSessionExtension.storeClientSession(orchClientSession);
        redis.addStateToRedis(STATE, SESSION_ID);
        if (incrementProcessIdentityAttempts) {
            var session = orchSessionExtension.getSession(SESSION_ID).orElseThrow();
            session.incrementProcessingIdentityAttempts();
            orchSessionExtension.updateSession(session);
        }
    }
}

package uk.gov.di.authentication.api;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.apache.http.client.utils.URIBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.app.lambda.DocAppCallbackHandler;
import uk.gov.di.orchestration.shared.entity.OrchClientSessionItem;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem;
import uk.gov.di.orchestration.shared.entity.ResponseHeaders;
import uk.gov.di.orchestration.shared.entity.VectorOfTrust;
import uk.gov.di.orchestration.shared.helpers.ClientSubjectHelper;
import uk.gov.di.orchestration.shared.helpers.SaltHelper;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.orchestration.sharedtest.extensions.CriStubExtension;
import uk.gov.di.orchestration.sharedtest.extensions.CrossBrowserStorageExtension;
import uk.gov.di.orchestration.sharedtest.extensions.DocumentAppCredentialStoreExtension;
import uk.gov.di.orchestration.sharedtest.extensions.OrchAuthCodeExtension;
import uk.gov.di.orchestration.sharedtest.extensions.OrchClientSessionExtension;
import uk.gov.di.orchestration.sharedtest.extensions.OrchSessionExtension;
import uk.gov.di.orchestration.sharedtest.extensions.SqsQueueExtension;
import uk.gov.di.orchestration.sharedtest.extensions.StateStorageExtension;
import uk.gov.di.orchestration.sharedtest.extensions.TokenSigningExtension;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.endsWith;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.app.domain.DocAppAuditableEvent.AUTH_CODE_ISSUED;
import static uk.gov.di.authentication.app.domain.DocAppAuditableEvent.DOC_APP_AUTHORISATION_RESPONSE_RECEIVED;
import static uk.gov.di.authentication.app.domain.DocAppAuditableEvent.DOC_APP_SUCCESSFUL_CREDENTIAL_RESPONSE_RECEIVED;
import static uk.gov.di.authentication.app.domain.DocAppAuditableEvent.DOC_APP_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED;
import static uk.gov.di.authentication.app.domain.DocAppAuditableEvent.DOC_APP_UNSUCCESSFUL_AUTHORISATION_RESPONSE_RECEIVED;
import static uk.gov.di.authentication.app.domain.DocAppAuditableEvent.DOC_APP_UNSUCCESSFUL_CREDENTIAL_RESPONSE_RECEIVED;
import static uk.gov.di.authentication.testsupport.helpers.OrchAuthCodeAssertionHelper.assertOrchAuthCodeSaved;
import static uk.gov.di.orchestration.sharedtest.helper.AuditAssertionsHelper.assertTxmaAuditEventsReceived;
import static uk.gov.di.orchestration.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class DocAppCallbackHandlerIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    public static final String SESSION_ID = "some-session-id";
    public static final String CLIENT_SESSION_ID = "some-client-session-id";
    public static final Scope SCOPE = new Scope(OIDCScopeValue.OPENID);
    public static final State RP_STATE = new State();
    public static final State DOC_APP_STATE = new State();
    private static final String SIGNING_KEY_ID = UUID.randomUUID().toString();
    public static Subject docAppSubjectId;
    private static final ECKey privateKey;

    static {
        try {
            privateKey = new ECKeyGenerator(Curve.P_256).keyID(SIGNING_KEY_ID).generate();
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }

    @RegisterExtension public static final CriStubExtension criStub = new CriStubExtension();

    @RegisterExtension
    protected static final DocumentAppCredentialStoreExtension credentialExtension =
            new DocumentAppCredentialStoreExtension(180);

    @RegisterExtension
    protected static final OrchSessionExtension orchSessionExtension = new OrchSessionExtension();

    @RegisterExtension
    protected static final OrchClientSessionExtension orchClientSessionExtension =
            new OrchClientSessionExtension();

    @RegisterExtension
    public static final OrchAuthCodeExtension orchAuthCodeExtension = new OrchAuthCodeExtension();

    @RegisterExtension
    public static final StateStorageExtension stateStorageExtension = new StateStorageExtension();

    @RegisterExtension
    public static final CrossBrowserStorageExtension crossBrowserStorageExtension =
            new CrossBrowserStorageExtension();

    protected static final ConfigurationService configurationService =
            new DocAppCallbackHandlerIntegrationTest.TestConfigurationService(
                    criStub,
                    externalTokenSigner,
                    ipvPrivateKeyJwtSigner,
                    spotQueue,
                    docAppPrivateKeyJwtSigner);

    private static final String CLIENT_ID = "test-client-id";
    private static final String CLIENT_NAME = "test-client-name";

    private static final String REDIRECT_URI = "http://localhost/redirect";

    @BeforeEach
    void setup() throws JOSEException {
        handler = new DocAppCallbackHandler(configurationService);
        docAppSubjectId =
                new Subject(
                        ClientSubjectHelper.calculatePairwiseIdentifier(
                                new Subject().getValue(),
                                "https://test.com",
                                SaltHelper.generateNewSalt()));
        criStub.init(privateKey, docAppSubjectId.getValue());
        clientStore.createClient().withClientId(CLIENT_ID).saveToDynamo();
        txmaAuditQueue.clear();
    }

    @Test
    void shouldRedirectToRpWhenSuccessfullyProcessedDocAppResponse() throws Json.JsonException {
        setupSession();

        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(
                                Optional.of(buildSessionCookie(SESSION_ID, CLIENT_SESSION_ID))),
                        constructQueryStringParameters());

        assertThat(response, hasStatus(302));
        assertThat(response.getHeaders().get(ResponseHeaders.LOCATION), startsWith(REDIRECT_URI));

        assertTxmaAuditEventsReceived(
                txmaAuditQueue,
                List.of(
                        DOC_APP_AUTHORISATION_RESPONSE_RECEIVED,
                        DOC_APP_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED,
                        DOC_APP_SUCCESSFUL_CREDENTIAL_RESPONSE_RECEIVED,
                        AUTH_CODE_ISSUED));

        var docAppCredential =
                documentAppCredentialStore.getOrchCredential(docAppSubjectId.getValue());
        assertTrue(docAppCredential.isPresent());
        assertThat(docAppCredential.get().getCredential().size(), equalTo(1));

        var orchDocAppCredential =
                documentAppCredentialStore.getOrchCredential(docAppSubjectId.getValue());
        assertTrue(orchDocAppCredential.isPresent());
        assertThat(orchDocAppCredential.get().getCredential().size(), equalTo(1));

        assertOrchAuthCodeSaved(orchAuthCodeExtension, response);
    }

    @Test
    void shouldRedirectToRpWhenSuccessfullyProcessedDocAppResponseUsingUserinfoV2Endpoint()
            throws Json.JsonException {
        handler = new DocAppCallbackHandler(configurationService);
        setupSession();

        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(
                                Optional.of(buildSessionCookie(SESSION_ID, CLIENT_SESSION_ID))),
                        constructQueryStringParameters());

        assertThat(response, hasStatus(302));
        assertThat(response.getHeaders().get(ResponseHeaders.LOCATION), startsWith(REDIRECT_URI));

        assertTxmaAuditEventsReceived(
                txmaAuditQueue,
                List.of(
                        DOC_APP_AUTHORISATION_RESPONSE_RECEIVED,
                        DOC_APP_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED,
                        DOC_APP_SUCCESSFUL_CREDENTIAL_RESPONSE_RECEIVED,
                        AUTH_CODE_ISSUED));

        var docAppCredential =
                documentAppCredentialStore.getOrchCredential(docAppSubjectId.getValue());
        assertTrue(docAppCredential.isPresent());
        assertThat(docAppCredential.get().getCredential().size(), equalTo(1));

        var orchDocAppCredential =
                documentAppCredentialStore.getOrchCredential(docAppSubjectId.getValue());
        assertTrue(orchDocAppCredential.isPresent());
        assertThat(orchDocAppCredential.get().getCredential().size(), equalTo(1));

        assertOrchAuthCodeSaved(orchAuthCodeExtension, response);
    }

    @Test
    void shouldThrowIfClientSessionAndUserInfoEndpointDocAppIdDoesNotMatch()
            throws Json.JsonException {
        setupSession();

        criStub.register(
                "/userinfo/v2",
                200,
                "application/json",
                "{\"sub\":\"'mockSubThatIsDifferentFromClientSessionDocAppUserId'\", \"https://vocab.account.gov.uk/v1/credentialJWT\": [\"'mockSignedJwtOne'\", \"'mockSignedJwtTwo'\"]}");

        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(
                                Optional.of(buildSessionCookie(SESSION_ID, CLIENT_SESSION_ID))),
                        constructQueryStringParameters());

        assertThat(response, hasStatus(302));
        assertThat(
                response.getHeaders().get(ResponseHeaders.LOCATION),
                startsWith(TEST_CONFIGURATION_SERVICE.getAuthFrontendBaseURL().toString()));
        assertThat(response.getHeaders().get(ResponseHeaders.LOCATION), endsWith("error"));

        assertTxmaAuditEventsReceived(
                txmaAuditQueue,
                List.of(
                        DOC_APP_AUTHORISATION_RESPONSE_RECEIVED,
                        DOC_APP_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED,
                        DOC_APP_UNSUCCESSFUL_CREDENTIAL_RESPONSE_RECEIVED));
    }

    @Test
    void shouldThrowIfInvalidResponseReceivedFromCriProtectedEndpoint() throws Json.JsonException {
        setupSession();

        criStub.register("/userinfo/v2", 200, "application/jwt", "invalid-response");

        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(
                                Optional.of(buildSessionCookie(SESSION_ID, CLIENT_SESSION_ID))),
                        constructQueryStringParameters());

        assertThat(response, hasStatus(302));
        assertThat(
                response.getHeaders().get(ResponseHeaders.LOCATION),
                startsWith(TEST_CONFIGURATION_SERVICE.getAuthFrontendBaseURL().toString()));
        assertThat(response.getHeaders().get(ResponseHeaders.LOCATION), endsWith("error"));

        assertTxmaAuditEventsReceived(
                txmaAuditQueue,
                List.of(
                        DOC_APP_AUTHORISATION_RESPONSE_RECEIVED,
                        DOC_APP_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED,
                        DOC_APP_UNSUCCESSFUL_CREDENTIAL_RESPONSE_RECEIVED));
    }

    @Test
    void shouldSendAuthenticationErrorResponseToRPWhenCRIRequestReturns404()
            throws Json.JsonException {
        setupSession();
        handler = new DocAppCallbackHandler(configurationService);

        criStub.register("/userinfo/v2", 404, "application/jwt", "error");

        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(
                                Optional.of(buildSessionCookie(SESSION_ID, CLIENT_SESSION_ID))),
                        constructQueryStringParameters());

        assertThat(response, hasStatus(302));
        assertThat(
                response.getHeaders().get(ResponseHeaders.LOCATION),
                startsWith(
                        TEST_CONFIGURATION_SERVICE.getDocAppAuthorisationCallbackURI().toString()));
        assertThat(
                response.getHeaders().get(ResponseHeaders.LOCATION),
                containsString("error=access_denied&error_description=Not+found&state="));

        assertTxmaAuditEventsReceived(
                txmaAuditQueue,
                List.of(
                        DOC_APP_AUTHORISATION_RESPONSE_RECEIVED,
                        DOC_APP_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED,
                        DOC_APP_UNSUCCESSFUL_AUTHORISATION_RESPONSE_RECEIVED));
    }

    @Test
    void shouldThrowIfErrorReceivedFromCriProtectedEndpoint() throws Json.JsonException {
        setupSession();

        criStub.register("/userinfo/v2", 400, "application/jwt", "error");

        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(
                                Optional.of(buildSessionCookie(SESSION_ID, CLIENT_SESSION_ID))),
                        constructQueryStringParameters());

        assertThat(response, hasStatus(302));
        assertThat(
                response.getHeaders().get(ResponseHeaders.LOCATION),
                startsWith(TEST_CONFIGURATION_SERVICE.getAuthFrontendBaseURL().toString()));
        assertThat(response.getHeaders().get(ResponseHeaders.LOCATION), endsWith("error"));

        assertTxmaAuditEventsReceived(
                txmaAuditQueue,
                List.of(
                        DOC_APP_AUTHORISATION_RESPONSE_RECEIVED,
                        DOC_APP_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED,
                        DOC_APP_UNSUCCESSFUL_CREDENTIAL_RESPONSE_RECEIVED));
    }

    @Test
    void shouldRedirectToRPWhenNoSessionCookieAndAccessDeniedErrorIsPresent()
            throws Json.JsonException {
        setupSession();
        crossBrowserStorageExtension.store(DOC_APP_STATE, CLIENT_SESSION_ID);

        var queryStringParameters =
                new HashMap<>(
                        Map.of(
                                "state",
                                DOC_APP_STATE.getValue(),
                                "error",
                                OAuth2Error.ACCESS_DENIED_CODE));
        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(Optional.empty()),
                        queryStringParameters);

        var error =
                new ErrorObject(
                        OAuth2Error.ACCESS_DENIED_CODE,
                        "Access denied for security reasons, a new authentication request may be successful");
        var expectedURI =
                new AuthenticationErrorResponse(URI.create(REDIRECT_URI), error, RP_STATE, null)
                        .toURI()
                        .toString();
        assertThat(response, hasStatus(302));
        assertThat(response.getHeaders().get(ResponseHeaders.LOCATION), equalTo(expectedURI));
    }

    private void setupSession() throws Json.JsonException {
        var authRequestBuilder =
                new AuthenticationRequest.Builder(
                                ResponseType.CODE,
                                SCOPE,
                                new ClientID(CLIENT_ID),
                                URI.create(REDIRECT_URI))
                        .state(RP_STATE)
                        .nonce(new Nonce());
        var clientSessionCreationDate =
                LocalDateTime.ofInstant(
                        Instant.parse("2025-02-19T15:00:00Z"), ZoneId.systemDefault());
        var orchClientSession =
                new OrchClientSessionItem(
                        CLIENT_SESSION_ID,
                        authRequestBuilder.build().toParameters(),
                        clientSessionCreationDate,
                        List.of(VectorOfTrust.getDefaults()),
                        CLIENT_NAME);
        orchClientSession.setDocAppSubjectId(docAppSubjectId.getValue());
        orchClientSessionExtension.storeClientSession(orchClientSession);
        stateStorageExtension.storeState("state:" + SESSION_ID, DOC_APP_STATE.getValue());
        orchSessionExtension.addSession(
                new OrchSessionItem(SESSION_ID)
                        .withAccountState(OrchSessionItem.AccountState.EXISTING_DOC_APP_JOURNEY));
    }

    private Map<String, String> constructQueryStringParameters() {
        final Map<String, String> queryStringParameters = new HashMap<>();
        queryStringParameters.putAll(
                Map.of(
                        "state",
                        DOC_APP_STATE.getValue(),
                        "code",
                        new AuthorizationCode().getValue()));
        return queryStringParameters;
    }

    protected static class TestConfigurationService extends IntegrationTestConfigurationService {

        private final CriStubExtension criStubExtension;

        public TestConfigurationService(
                CriStubExtension criStubExtension,
                TokenSigningExtension tokenSigningKey,
                TokenSigningExtension ipvPrivateKeyJwtSigner,
                SqsQueueExtension spotQueue,
                TokenSigningExtension docAppPrivateKeyJwtSigner) {
            super(
                    tokenSigningKey,
                    storageTokenSigner,
                    ipvPrivateKeyJwtSigner,
                    spotQueue,
                    docAppPrivateKeyJwtSigner,
                    configurationParameters);
            this.criStubExtension = criStubExtension;
        }

        @Override
        public URI getDocAppBackendURI() {
            try {
                return new URIBuilder()
                        .setHost("localhost")
                        .setPort(criStubExtension.getHttpPort())
                        .setScheme("http")
                        .build();
            } catch (URISyntaxException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public String getDocAppAuthorisationClientId() {
            return CLIENT_ID;
        }

        @Override
        public URI getDocAppAuthorisationCallbackURI() {
            return URI.create("http://localhost/redirect");
        }

        @Override
        public String getTxmaAuditQueueUrl() {
            return txmaAuditQueue.getQueueUrl();
        }

        @Override
        public boolean isCustomDocAppClaimEnabled() {
            return true;
        }

        @Override
        public String getDocAppCriV2DataEndpoint() {
            return "/userinfo/v2";
        }
    }
}

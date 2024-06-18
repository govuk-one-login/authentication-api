package uk.gov.di.authentication.api;

import com.google.gson.internal.LinkedTreeMap;
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
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import net.minidev.json.JSONArray;
import org.apache.http.client.utils.URIBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import uk.gov.di.authentication.ipv.entity.LogIds;
import uk.gov.di.authentication.ipv.entity.SPOTRequest;
import uk.gov.di.authentication.ipv.lambda.IPVCallbackHandler;
import uk.gov.di.authentication.testsupport.helpers.SpotQueueAssertionHelper;
import uk.gov.di.orchestration.shared.entity.ClientType;
import uk.gov.di.orchestration.shared.entity.IdentityCredentials;
import uk.gov.di.orchestration.shared.entity.LevelOfConfidence;
import uk.gov.di.orchestration.shared.entity.ResponseHeaders;
import uk.gov.di.orchestration.shared.entity.ServiceType;
import uk.gov.di.orchestration.shared.entity.ValidClaims;
import uk.gov.di.orchestration.shared.helpers.IdGenerator;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.orchestration.sharedtest.extensions.IPVStubExtension;
import uk.gov.di.orchestration.sharedtest.extensions.KmsKeyExtension;
import uk.gov.di.orchestration.sharedtest.extensions.SnsTopicExtension;
import uk.gov.di.orchestration.sharedtest.extensions.SqsQueueExtension;
import uk.gov.di.orchestration.sharedtest.extensions.TokenSigningExtension;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static java.util.Collections.emptyMap;
import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.ipv.domain.IPVAuditableEvent.AUTH_CODE_ISSUED;
import static uk.gov.di.authentication.ipv.domain.IPVAuditableEvent.IPV_AUTHORISATION_RESPONSE_RECEIVED;
import static uk.gov.di.authentication.ipv.domain.IPVAuditableEvent.IPV_SPOT_REQUESTED;
import static uk.gov.di.authentication.ipv.domain.IPVAuditableEvent.IPV_SUCCESSFUL_IDENTITY_RESPONSE_RECEIVED;
import static uk.gov.di.authentication.ipv.domain.IPVAuditableEvent.IPV_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED;
import static uk.gov.di.authentication.ipv.domain.IPVAuditableEvent.IPV_UNSUCCESSFUL_AUTHORISATION_RESPONSE_RECEIVED;
import static uk.gov.di.orchestration.shared.entity.IdentityClaims.VOT;
import static uk.gov.di.orchestration.shared.entity.IdentityClaims.VTM;
import static uk.gov.di.orchestration.shared.helpers.ClientSubjectHelper.calculatePairwiseIdentifier;
import static uk.gov.di.orchestration.sharedtest.helper.AuditAssertionsHelper.assertTxmaAuditEventsReceived;
import static uk.gov.di.orchestration.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class IPVCallbackHandlerIntegrationTest extends ApiGatewayHandlerIntegrationTest {
    private static final String ARBITRARY_UNIX_TIMESTAMP = "1700558480962";
    private static final String PERSISTENT_SESSION_ID =
            IdGenerator.generate() + "--" + ARBITRARY_UNIX_TIMESTAMP;

    @RegisterExtension public static final IPVStubExtension ipvStub = new IPVStubExtension();

    protected final ConfigurationService configurationService =
            new IPVCallbackHandlerIntegrationTest.TestConfigurationService(
                    ipvStub,
                    auditTopic,
                    notificationsQueue,
                    auditSigningKey,
                    externalTokenSigner,
                    ipvPrivateKeyJwtSigner,
                    spotQueue);

    private static final String CLIENT_ID = "test-client-id";
    private static final String EMAIL = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String REDIRECT_URI = "http://localhost/redirect";
    private static final String TEST_EMAIL_ADDRESS = "test@test.com";
    private static final Subject INTERNAL_SUBJECT = new Subject();
    public static final String CLIENT_NAME = "test-client-name";
    public static final String CLIENT_SESSION_ID = "some-client-session-id";
    public static final State RP_STATE = new State();
    public static final State ORCHESTRATION_STATE = new State();

    @BeforeEach
    void setup() {
        ipvStub.init();
        handler = new IPVCallbackHandler(configurationService);
        txmaAuditQueue.clear();
        spotQueue.clear();
    }

    @Test
    void shouldRedirectToLoginWhenSuccessfullyProcessedIpvResponse() throws Json.JsonException {
        var sessionId = "some-session-id";
        var sectorId = "test.com";
        var scope = new Scope(OIDCScopeValue.OPENID);
        var authRequestBuilder =
                new AuthenticationRequest.Builder(
                                ResponseType.CODE,
                                scope,
                                new ClientID(CLIENT_ID),
                                URI.create(REDIRECT_URI))
                        .nonce(new Nonce())
                        .state(RP_STATE);
        redis.createSession(sessionId);
        redis.createClientSession(
                CLIENT_SESSION_ID, CLIENT_NAME, authRequestBuilder.build().toParameters());
        redis.addStateToRedis(ORCHESTRATION_STATE, sessionId);
        redis.addEmailToSession(sessionId, TEST_EMAIL_ADDRESS);
        setUpDynamo();
        var salt = userStore.addSalt(TEST_EMAIL_ADDRESS);

        var response =
                makeRequest(
                        Optional.empty(),
                        Map.of(
                                "Cookie",
                                format(
                                        "gs=%s.%s;di-persistent-session-id=%s",
                                        sessionId, CLIENT_SESSION_ID, PERSISTENT_SESSION_ID)),
                        new HashMap<>(
                                Map.of(
                                        "state",
                                        ORCHESTRATION_STATE.getValue(),
                                        "code",
                                        new AuthorizationCode().getValue())));

        assertThat(response, hasStatus(302));
        assertThat(
                response.getHeaders().get(ResponseHeaders.LOCATION),
                startsWith(TEST_CONFIGURATION_SERVICE.getLoginURI().toString()));

        assertTxmaAuditEventsReceived(
                txmaAuditQueue,
                List.of(
                        IPV_AUTHORISATION_RESPONSE_RECEIVED,
                        IPV_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED,
                        IPV_SUCCESSFUL_IDENTITY_RESPONSE_RECEIVED,
                        IPV_SPOT_REQUESTED));
        var pairwiseIdentifier =
                calculatePairwiseIdentifier(INTERNAL_SUBJECT.getValue(), "test.com", salt);
        SpotQueueAssertionHelper.assertSpotRequestReceived(
                spotQueue,
                List.of(
                        new SPOTRequest(
                                Map.of(
                                        VOT.getValue(),
                                        LevelOfConfidence.MEDIUM_LEVEL.toString(),
                                        VTM.getValue(),
                                        "/trustmark"),
                                INTERNAL_SUBJECT.getValue(),
                                salt,
                                sectorId,
                                pairwiseIdentifier,
                                new LogIds(
                                        sessionId,
                                        PERSISTENT_SESSION_ID,
                                        "request-i",
                                        CLIENT_ID,
                                        CLIENT_SESSION_ID),
                                CLIENT_ID)));

        var identityCredentials = identityStore.getIdentityCredentials(pairwiseIdentifier);

        assertTrue(
                identityCredentials
                        .map(IdentityCredentials::getAdditionalClaims)
                        .map(t -> t.get(ValidClaims.ADDRESS.getValue()))
                        .isPresent());
        assertTrue(
                identityCredentials
                        .map(IdentityCredentials::getAdditionalClaims)
                        .map(t -> t.get(ValidClaims.PASSPORT.getValue()))
                        .isPresent());
        assertTrue(
                identityCredentials
                        .map(IdentityCredentials::getAdditionalClaims)
                        .map(t -> t.get(ValidClaims.DRIVING_PERMIT.getValue()))
                        .isPresent());
        assertTrue(
                identityCredentials
                        .map(IdentityCredentials::getAdditionalClaims)
                        .map(t -> t.get(ValidClaims.SOCIAL_SECURITY_RECORD.getValue()))
                        .isPresent());
        assertTrue(
                identityCredentials
                        .map(IdentityCredentials::getAdditionalClaims)
                        .map(t -> t.get(ValidClaims.RETURN_CODE.getValue()))
                        .isPresent());

        var addressClaim =
                objectMapper.readValue(
                        identityCredentials
                                .get()
                                .getAdditionalClaims()
                                .get(ValidClaims.ADDRESS.getValue()),
                        JSONArray.class);
        assertThat(((LinkedTreeMap) addressClaim.get(0)).size(), equalTo(8));

        var passportClaim =
                objectMapper.readValue(
                        identityCredentials
                                .get()
                                .getAdditionalClaims()
                                .get(ValidClaims.PASSPORT.getValue()),
                        JSONArray.class);
        assertThat(((LinkedTreeMap) passportClaim.get(0)).size(), equalTo(2));

        var drivingPermit =
                objectMapper.readValue(
                        identityCredentials
                                .get()
                                .getAdditionalClaims()
                                .get(ValidClaims.DRIVING_PERMIT.getValue()),
                        JSONArray.class);
        assertThat(((LinkedTreeMap) drivingPermit.get(0)).size(), equalTo(6));

        var socialSecurityRecord =
                objectMapper.readValue(
                        identityCredentials
                                .get()
                                .getAdditionalClaims()
                                .get(ValidClaims.SOCIAL_SECURITY_RECORD.getValue()),
                        JSONArray.class);
        assertThat(((LinkedTreeMap) socialSecurityRecord.get(0)).size(), equalTo(1));

        var returnCode =
                objectMapper.readValue(
                        identityCredentials
                                .get()
                                .getAdditionalClaims()
                                .get(ValidClaims.RETURN_CODE.getValue()),
                        JSONArray.class);
        assertThat(returnCode.size(), equalTo(2));
    }

    @Test
    void
            shouldRedirectToRPWhenNoSessionCookieAndCallToNoSessionOrchestrationServiceReturnsNoSessionEntity()
                    throws Json.JsonException {
        var scope = new Scope(OIDCScopeValue.OPENID);
        var authRequestBuilder =
                new AuthenticationRequest.Builder(
                                ResponseType.CODE,
                                scope,
                                new ClientID(CLIENT_ID),
                                URI.create(REDIRECT_URI))
                        .nonce(new Nonce())
                        .state(RP_STATE);
        redis.createClientSession(
                CLIENT_SESSION_ID, CLIENT_NAME, authRequestBuilder.build().toParameters());
        redis.addClientSessionAndStateToRedis(ORCHESTRATION_STATE, CLIENT_SESSION_ID);

        var response =
                makeRequest(
                        Optional.empty(),
                        emptyMap(),
                        new HashMap<>(
                                Map.of(
                                        "state",
                                        ORCHESTRATION_STATE.getValue(),
                                        "error",
                                        "access_denied")));

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
        assertTxmaAuditEventsReceived(
                txmaAuditQueue, singletonList(IPV_UNSUCCESSFUL_AUTHORISATION_RESPONSE_RECEIVED));
    }

    @Test
    void
            shouldRedirectToFrontendErrorPageWhenNoSessionCookieButClientSessionNotFoundWithGivenState()
                    throws Json.JsonException {
        var scope = new Scope(OIDCScopeValue.OPENID);
        var authRequestBuilder =
                new AuthenticationRequest.Builder(
                                ResponseType.CODE,
                                scope,
                                new ClientID(CLIENT_ID),
                                URI.create(REDIRECT_URI))
                        .nonce(new Nonce())
                        .state(RP_STATE);
        redis.createClientSession(
                CLIENT_SESSION_ID, CLIENT_NAME, authRequestBuilder.build().toParameters());

        var response =
                makeRequest(
                        Optional.empty(),
                        emptyMap(),
                        new HashMap<>(
                                Map.of(
                                        "state",
                                        ORCHESTRATION_STATE.getValue(),
                                        "error",
                                        "access_denied")));

        assertThat(response, hasStatus(302));
        assertThat(
                response.getHeaders().get(ResponseHeaders.LOCATION),
                startsWith(TEST_CONFIGURATION_SERVICE.getLoginURI().toString()));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldStoreReturnCodesInDynamoWhenTheyArePresent(boolean validLoC)
            throws Json.JsonException {
        if (validLoC) {
            ipvStub.initWithValidLoCAndReturnCode();
        } else {
            ipvStub.initWithInvalidLoCAndReturnCode();
        }

        var sessionId = "some-session-id";
        var scope = new Scope(OIDCScopeValue.OPENID);
        var oidcValidClaimsRequest =
                new OIDCClaimsRequest()
                        .withUserInfoClaimsRequest(
                                new ClaimsSetRequest().add(ValidClaims.RETURN_CODE.getValue()));
        var authRequestBuilder =
                new AuthenticationRequest.Builder(
                                ResponseType.CODE,
                                scope,
                                new ClientID(CLIENT_ID),
                                URI.create(REDIRECT_URI))
                        .nonce(new Nonce())
                        .state(RP_STATE)
                        .claims(oidcValidClaimsRequest);
        redis.createSession(sessionId);
        redis.createClientSession(
                CLIENT_SESSION_ID, CLIENT_NAME, authRequestBuilder.build().toParameters());
        redis.addStateToRedis(ORCHESTRATION_STATE, sessionId);
        redis.addEmailToSession(sessionId, TEST_EMAIL_ADDRESS);
        setUpDynamo();
        var salt = userStore.addSalt(TEST_EMAIL_ADDRESS);
        var pairwiseIdentifier =
                calculatePairwiseIdentifier(INTERNAL_SUBJECT.getValue(), "test.com", salt);
        var response =
                makeRequest(
                        Optional.empty(),
                        Map.of(
                                "Cookie",
                                format(
                                        "gs=%s.%s;di-persistent-session-id=%s",
                                        sessionId, CLIENT_SESSION_ID, PERSISTENT_SESSION_ID)),
                        new HashMap<>(
                                Map.of(
                                        "state",
                                        ORCHESTRATION_STATE.getValue(),
                                        "code",
                                        new AuthorizationCode().getValue())));

        var identityCredentials = identityStore.getIdentityCredentials(pairwiseIdentifier);

        assertThat(response, hasStatus(302));
        if (validLoC) {
            assertThat(
                    response.getHeaders().get(ResponseHeaders.LOCATION),
                    startsWith(TEST_CONFIGURATION_SERVICE.getLoginURI().toString()));

            assertTxmaAuditEventsReceived(
                    txmaAuditQueue,
                    List.of(
                            IPV_AUTHORISATION_RESPONSE_RECEIVED,
                            IPV_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED,
                            IPV_SUCCESSFUL_IDENTITY_RESPONSE_RECEIVED,
                            IPV_SPOT_REQUESTED));
        } else {
            assertThat(
                    response.getHeaders().get(ResponseHeaders.LOCATION), startsWith(REDIRECT_URI));

            assertTxmaAuditEventsReceived(
                    txmaAuditQueue,
                    List.of(
                            IPV_AUTHORISATION_RESPONSE_RECEIVED,
                            IPV_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED,
                            IPV_SUCCESSFUL_IDENTITY_RESPONSE_RECEIVED,
                            AUTH_CODE_ISSUED));
        }

        assertTrue(
                identityCredentials
                        .map(IdentityCredentials::getAdditionalClaims)
                        .map(t -> t.get(ValidClaims.RETURN_CODE.getValue()))
                        .isPresent());
        var returnCode =
                objectMapper.readValue(
                        identityCredentials
                                .get()
                                .getAdditionalClaims()
                                .get(ValidClaims.RETURN_CODE.getValue()),
                        JSONArray.class);
        assertThat(returnCode.size(), equalTo(1));
    }

    @Test
    void shouldBypassSPoTAndReturnAuthCodeIfIPVReturnsP0ButReturnCodeIsPresentAndRequested()
            throws Json.JsonException {
        ipvStub.initWithInvalidLoCAndReturnCode();

        var sessionId = "some-session-id";
        var scope = new Scope(OIDCScopeValue.OPENID);
        var oidcValidClaimsRequest =
                new OIDCClaimsRequest()
                        .withUserInfoClaimsRequest(
                                new ClaimsSetRequest().add(ValidClaims.RETURN_CODE.getValue()));
        var authRequestBuilder =
                new AuthenticationRequest.Builder(
                                ResponseType.CODE,
                                scope,
                                new ClientID(CLIENT_ID),
                                URI.create(REDIRECT_URI))
                        .nonce(new Nonce())
                        .state(RP_STATE)
                        .claims(oidcValidClaimsRequest);

        redis.createSession(sessionId);
        redis.createClientSession(
                CLIENT_SESSION_ID, CLIENT_NAME, authRequestBuilder.build().toParameters());
        redis.addStateToRedis(ORCHESTRATION_STATE, sessionId);
        redis.addEmailToSession(sessionId, TEST_EMAIL_ADDRESS);
        setUpDynamo();
        var response =
                makeRequest(
                        Optional.empty(),
                        Map.of(
                                "Cookie",
                                format(
                                        "gs=%s.%s;di-persistent-session-id=%s",
                                        sessionId, CLIENT_SESSION_ID, PERSISTENT_SESSION_ID)),
                        new HashMap<>(
                                Map.of(
                                        "state",
                                        ORCHESTRATION_STATE.getValue(),
                                        "code",
                                        new AuthorizationCode().getValue())));

        assertThat(response, hasStatus(302));

        assertThat(spotQueue.getApproximateMessageCount(), equalTo(0));

        assertThat(
                response.getHeaders().get(ResponseHeaders.LOCATION),
                startsWith(REDIRECT_URI + "?code"));
    }

    @Test
    void
            shouldBypassSPoTAndReturnAccessDeniedErrorIfIPVReturnsP0AndReturnCodeIsPresentButNotRequested()
                    throws Json.JsonException {
        ipvStub.initWithInvalidLoCAndReturnCode();

        var sessionId = "some-session-id";
        var scope = new Scope(OIDCScopeValue.OPENID);
        var authRequestBuilder =
                new AuthenticationRequest.Builder(
                                ResponseType.CODE,
                                scope,
                                new ClientID(CLIENT_ID),
                                URI.create(REDIRECT_URI))
                        .nonce(new Nonce())
                        .state(RP_STATE);

        redis.createSession(sessionId);
        redis.createClientSession(
                CLIENT_SESSION_ID, CLIENT_NAME, authRequestBuilder.build().toParameters());
        redis.addStateToRedis(ORCHESTRATION_STATE, sessionId);
        redis.addEmailToSession(sessionId, TEST_EMAIL_ADDRESS);
        setUpDynamo();
        var response =
                makeRequest(
                        Optional.empty(),
                        Map.of(
                                "Cookie",
                                format(
                                        "gs=%s.%s;di-persistent-session-id=%s",
                                        sessionId, CLIENT_SESSION_ID, PERSISTENT_SESSION_ID)),
                        new HashMap<>(
                                Map.of(
                                        "state",
                                        ORCHESTRATION_STATE.getValue(),
                                        "code",
                                        new AuthorizationCode().getValue())));

        assertThat(response, hasStatus(302));

        assertThat(spotQueue.getApproximateMessageCount(), equalTo(0));

        assertThat(
                response.getHeaders().get(ResponseHeaders.LOCATION),
                startsWith(REDIRECT_URI + "?error=access_denied"));
    }

    private void setUpDynamo() {
        userStore.signUp(TEST_EMAIL_ADDRESS, "password", INTERNAL_SUBJECT);
        clientStore.registerClient(
                CLIENT_ID,
                "test-client",
                singletonList(REDIRECT_URI),
                singletonList(EMAIL),
                singletonList("openid"),
                null,
                singletonList("http://localhost/post-redirect-logout"),
                "http://example.com",
                String.valueOf(ServiceType.MANDATORY),
                "https://test.com",
                "pairwise",
                ClientType.WEB,
                List.of("https://vocab.account.gov.uk/v1/returnCode"),
                false,
                List.of("P0", "P2"));
    }

    protected static class TestConfigurationService extends IntegrationTestConfigurationService {

        private final IPVStubExtension ipvStubExtension;

        public TestConfigurationService(
                IPVStubExtension ipvStub,
                SnsTopicExtension auditEventTopic,
                SqsQueueExtension notificationQueue,
                KmsKeyExtension auditSigningKey,
                TokenSigningExtension tokenSigningKey,
                TokenSigningExtension ipvPrivateKeyJwtSigner,
                SqsQueueExtension spotQueue) {
            super(
                    tokenSigningKey,
                    storageTokenSigner,
                    ipvPrivateKeyJwtSigner,
                    spotQueue,
                    docAppPrivateKeyJwtSigner,
                    configurationParameters);
            this.ipvStubExtension = ipvStub;
        }

        @Override
        public URI getIPVBackendURI() {
            try {
                return new URIBuilder()
                        .setHost("localhost")
                        .setPort(ipvStubExtension.getHttpPort())
                        .setScheme("http")
                        .build();
            } catch (URISyntaxException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public String getIPVAudience() {
            try {
                return new URIBuilder()
                        .setHost("localhost")
                        .setPort(ipvStubExtension.getHttpPort())
                        .setScheme("http")
                        .build()
                        .toString();
            } catch (URISyntaxException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public String getIPVAuthorisationClientId() {
            return "ipv-client-id";
        }

        @Override
        public URI getIPVAuthorisationCallbackURI() {
            return URI.create("http://localhost/redirect");
        }

        @Override
        public boolean isIdentityEnabled() {
            return true;
        }

        @Override
        public String getTxmaAuditQueueUrl() {
            return txmaAuditQueue.getQueueUrl();
        }

        @Override
        public boolean isIPVNoSessionResponseEnabled() {
            return true;
        }
    }
}

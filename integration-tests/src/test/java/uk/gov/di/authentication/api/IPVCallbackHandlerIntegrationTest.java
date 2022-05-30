package uk.gov.di.authentication.api;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.apache.http.client.utils.URIBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.ipv.entity.LogIds;
import uk.gov.di.authentication.ipv.entity.SPOTRequest;
import uk.gov.di.authentication.ipv.lambda.IPVCallbackHandler;
import uk.gov.di.authentication.shared.entity.LevelOfConfidence;
import uk.gov.di.authentication.shared.entity.ResponseHeaders;
import uk.gov.di.authentication.shared.entity.ServiceType;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.IPVStubExtension;
import uk.gov.di.authentication.sharedtest.extensions.KmsKeyExtension;
import uk.gov.di.authentication.sharedtest.extensions.SnsTopicExtension;
import uk.gov.di.authentication.sharedtest.extensions.SqsQueueExtension;
import uk.gov.di.authentication.sharedtest.extensions.TokenSigningExtension;
import uk.gov.di.authentication.testsupport.helpers.SpotQueueAssertionHelper;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.startsWith;
import static uk.gov.di.authentication.ipv.domain.IPVAuditableEvent.IPV_AUTHORISATION_RESPONSE_RECEIVED;
import static uk.gov.di.authentication.ipv.domain.IPVAuditableEvent.IPV_SPOT_REQUESTED;
import static uk.gov.di.authentication.ipv.domain.IPVAuditableEvent.IPV_SUCCESSFUL_IDENTITY_RESPONSE_RECEIVED;
import static uk.gov.di.authentication.ipv.domain.IPVAuditableEvent.IPV_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED;
import static uk.gov.di.authentication.shared.entity.IdentityClaims.VOT;
import static uk.gov.di.authentication.shared.entity.IdentityClaims.VTM;
import static uk.gov.di.authentication.shared.helpers.ClientSubjectHelper.calculatePairwiseIdentifier;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertEventTypesReceived;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class IPVCallbackHandlerIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    @RegisterExtension public static final IPVStubExtension ipvStub = new IPVStubExtension();

    protected final ConfigurationService configurationService =
            new IPVCallbackHandlerIntegrationTest.TestConfigurationService(
                    ipvStub,
                    auditTopic,
                    notificationsQueue,
                    auditSigningKey,
                    tokenSigner,
                    ipvPrivateKeyJwtSigner,
                    spotQueue);

    private static final String CLIENT_ID = "test-client-id";
    private static final String EMAIL = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String REDIRECT_URI = "http://localhost/redirect";
    private static final String TEST_EMAIL_ADDRESS = "test@test.com";
    private static final Subject INTERNAL_SUBJECT = new Subject();

    @BeforeEach
    void setup() {
        ipvStub.init();
        handler = new IPVCallbackHandler(configurationService);
    }

    @Test
    void shouldRedirectToLoginWhenSuccessfullyProcessedIpvResponse() throws Json.JsonException {
        var sessionId = "some-session-id";
        var clientSessionId = "some-client-session-id";
        var persistentSessionId = "persistent-id-value";
        var sectorId = "test.com";
        var scope = new Scope(OIDCScopeValue.OPENID);
        var authRequestBuilder =
                new AuthenticationRequest.Builder(
                                ResponseType.CODE,
                                scope,
                                new ClientID(CLIENT_ID),
                                URI.create(REDIRECT_URI))
                        .nonce(new Nonce());
        var state = new State();
        redis.createSession(sessionId);
        redis.createClientSession(clientSessionId, authRequestBuilder.build().toParameters());
        redis.addStateToRedis(state, sessionId);
        redis.addEmailToSession(sessionId, TEST_EMAIL_ADDRESS);
        setUpDynamo();
        var salt = addSalt();

        var response =
                makeRequest(
                        Optional.empty(),
                        Map.of(
                                "Cookie",
                                format(
                                        "gs=%s.%s;di-persistent-session-id=%s",
                                        sessionId, clientSessionId, persistentSessionId)),
                        constructQueryStringParameters(state));

        assertThat(response, hasStatus(302));
        assertThat(
                response.getHeaders().get(ResponseHeaders.LOCATION),
                startsWith(TEST_CONFIGURATION_SERVICE.getLoginURI().toString()));

        assertEventTypesReceived(
                auditTopic,
                List.of(
                        IPV_AUTHORISATION_RESPONSE_RECEIVED,
                        IPV_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED,
                        IPV_SUCCESSFUL_IDENTITY_RESPONSE_RECEIVED,
                        IPV_SPOT_REQUESTED));
        SpotQueueAssertionHelper.assertSpotRequestReceived(
                spotQueue,
                List.of(
                        new SPOTRequest(
                                Map.of(
                                        VOT.getValue(),
                                        LevelOfConfidence.MEDIUM_LEVEL.getValue(),
                                        VTM.getValue(),
                                        "/trustmark"),
                                INTERNAL_SUBJECT.getValue(),
                                salt,
                                sectorId,
                                calculatePairwiseIdentifier(
                                        INTERNAL_SUBJECT.getValue(), "test.com", salt),
                                new LogIds(
                                        sessionId, persistentSessionId, "request-i", CLIENT_ID))));
    }

    private String setUpDynamo() {
        var publicSubject = userStore.signUp(TEST_EMAIL_ADDRESS, "password", INTERNAL_SUBJECT);
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
                true);
        return publicSubject;
    }

    private byte[] addSalt() {
        return userStore.addSalt(TEST_EMAIL_ADDRESS);
    }

    private Map<String, String> constructQueryStringParameters(State state) {
        final Map<String, String> queryStringParameters = new HashMap<>();
        queryStringParameters.putAll(
                Map.of("state", state.getValue(), "code", new AuthorizationCode().getValue()));
        return queryStringParameters;
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
                    auditEventTopic,
                    notificationQueue,
                    auditSigningKey,
                    tokenSigningKey,
                    ipvPrivateKeyJwtSigner,
                    spotQueue,
                    docAppPrivateKeyJwtSigner);
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
    }
}

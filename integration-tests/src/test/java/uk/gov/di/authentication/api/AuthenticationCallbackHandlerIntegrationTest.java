package uk.gov.di.authentication.api;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.OAuth2Error;
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
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.ipv.domain.IPVAuditableEvent;
import uk.gov.di.authentication.oidc.domain.OidcAuditableEvent;
import uk.gov.di.authentication.oidc.domain.OrchestrationAuditableEvent;
import uk.gov.di.authentication.oidc.entity.AuthenticationUserInfo;
import uk.gov.di.authentication.oidc.lambda.AuthenticationCallbackHandler;
import uk.gov.di.authentication.oidc.services.AuthenticationAuthorizationService;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.ClientType;
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;
import uk.gov.di.authentication.shared.entity.LevelOfConfidence;
import uk.gov.di.authentication.shared.entity.ResponseHeaders;
import uk.gov.di.authentication.shared.entity.ServiceType;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.AuthExternalApiStubExtension;
import uk.gov.di.authentication.sharedtest.extensions.AuthenticationCallbackUserInfoStoreExtension;
import uk.gov.di.authentication.sharedtest.extensions.KmsKeyExtension;
import uk.gov.di.authentication.sharedtest.extensions.SnsTopicExtension;
import uk.gov.di.authentication.sharedtest.extensions.SqsQueueExtension;
import uk.gov.di.authentication.sharedtest.extensions.TokenSigningExtension;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.endsWith;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertTxmaAuditEventsReceived;
import static uk.gov.di.authentication.sharedtest.helper.JsonArrayHelper.jsonArrayOf;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class AuthenticationCallbackHandlerIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    public static final String SESSION_ID = "some-session-id";
    public static final String CLIENT_SESSION_ID = "some-client-session-id";
    public static final Scope SCOPE = new Scope(OIDCScopeValue.OPENID);
    public static final State RP_STATE = new State();
    public static final State ORCH_TO_AUTH_STATE = new State();

    @RegisterExtension
    public final AuthExternalApiStubExtension authExternalApiStub =
            new AuthExternalApiStubExtension();

    @RegisterExtension
    protected final AuthenticationCallbackUserInfoStoreExtension userInfoStoreExtension =
            new AuthenticationCallbackUserInfoStoreExtension(180);

    protected final ConfigurationService configurationService =
            new AuthenticationCallbackHandlerIntegrationTest.TestConfigurationService(
                    authExternalApiStub,
                    auditTopic,
                    notificationsQueue,
                    auditSigningKey,
                    tokenSigner,
                    ipvPrivateKeyJwtSigner,
                    spotQueue,
                    docAppPrivateKeyJwtSigner);

    private static final String CLIENT_ID = "test-client-id";
    private static final String CLIENT_NAME = "test-client-name";

    private static final URI REDIRECT_URI = URI.create("http://localhost/redirect");
    private static final Subject SUBJECT_ID = new Subject();

    private static final String IPV_CLIENT_ID = "ipv-client-id";
    private static final KeyPair keyPair = generateRsaKeyPair();
    private static final String publicKey =
            "-----BEGIN PUBLIC KEY-----\n"
                    + Base64.getMimeEncoder().encodeToString(keyPair.getPublic().getEncoded())
                    + "\n-----END PUBLIC KEY-----\n";

    @Nested
    class AuthJourney {

        @BeforeEach()
        void authSetup() throws Json.JsonException {
            setupTest();
            setupSession();
            setupClientRegWithoutIdentityVerificationSupported();
        }

        @Test
        void shouldStoreUserInfoAndRedirectToRpWhenSuccessfullyProcessedCallbackResponse() {
            var response =
                    makeRequest(
                            Optional.empty(),
                            constructHeaders(
                                    Optional.of(buildSessionCookie(SESSION_ID, CLIENT_SESSION_ID))),
                            constructQueryStringParameters());

            assertThat(response, hasStatus(302));

            URI redirectLocationHeader =
                    URI.create(response.getHeaders().get(ResponseHeaders.LOCATION));
            assertEquals(
                    REDIRECT_URI.getAuthority() + REDIRECT_URI.getPath(),
                    redirectLocationHeader.getAuthority() + redirectLocationHeader.getPath());

            assertThat(redirectLocationHeader.getQuery(), containsString(RP_STATE.getValue()));

            assertThat(redirectLocationHeader.getQuery(), containsString("code"));

            assertTxmaAuditEventsReceived(
                    txmaAuditQueue,
                    List.of(
                            OrchestrationAuditableEvent.AUTH_CALLBACK_RESPONSE_RECEIVED,
                            OrchestrationAuditableEvent.AUTH_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED,
                            OrchestrationAuditableEvent.AUTH_SUCCESSFUL_USERINFO_RESPONSE_RECEIVED,
                            OidcAuditableEvent.AUTH_CODE_ISSUED));

            Optional<AuthenticationUserInfo> userInfoDbEntry =
                    userInfoStoreExtension.getUserInfoBySubjectId(SUBJECT_ID.getValue());
            assertTrue(userInfoDbEntry.isPresent());
            assertEquals(SUBJECT_ID.getValue(), userInfoDbEntry.get().getSubjectID());
            assertThat(userInfoDbEntry.get().getUserInfo(), containsString("new_account"));
        }

        @Test
        void shouldRedirectToRpWithErrorWhenStateIsInvalid() {
            var response =
                    makeRequest(
                            Optional.empty(),
                            constructHeaders(
                                    Optional.of(buildSessionCookie(SESSION_ID, CLIENT_SESSION_ID))),
                            Map.of("code", "a-random-code", "state", new State().getValue()));

            assertThat(response, hasStatus(302));
            assertThat(
                    response.getHeaders().get(ResponseHeaders.LOCATION),
                    startsWith(REDIRECT_URI.toString()));
            assertThat(
                    response.getHeaders().get(ResponseHeaders.LOCATION),
                    containsString(OAuth2Error.SERVER_ERROR.getCode()));
            assertThat(
                    response.getHeaders().get(ResponseHeaders.LOCATION),
                    containsString(RP_STATE.getValue()));

            assertTxmaAuditEventsReceived(
                    txmaAuditQueue,
                    List.of(
                            OrchestrationAuditableEvent
                                    .AUTH_UNSUCCESSFUL_CALLBACK_RESPONSE_RECEIVED));

            Optional<AuthenticationUserInfo> userInfoDbEntry =
                    userInfoStoreExtension.getUserInfoBySubjectId(SUBJECT_ID.getValue());
            assertFalse(userInfoDbEntry.isPresent());
        }

        @Test
        void shouldRedirectToFrontendErrorPageIfUnsuccessfulResponseReceivedFromTokenEndpoint() {
            authExternalApiStub.register(
                    "/token", 400, "application/json", "{\"error\": \"invalid_request\"}");

            var response =
                    makeRequest(
                            Optional.empty(),
                            constructHeaders(
                                    Optional.of(buildSessionCookie(SESSION_ID, CLIENT_SESSION_ID))),
                            constructQueryStringParameters());

            assertThat(response, hasStatus(302));
            assertThat(
                    response.getHeaders().get(ResponseHeaders.LOCATION),
                    startsWith(TEST_CONFIGURATION_SERVICE.getLoginURI().toString()));
            assertThat(response.getHeaders().get(ResponseHeaders.LOCATION), endsWith("error"));

            assertTxmaAuditEventsReceived(
                    txmaAuditQueue,
                    List.of(
                            OrchestrationAuditableEvent.AUTH_CALLBACK_RESPONSE_RECEIVED,
                            OrchestrationAuditableEvent.AUTH_UNSUCCESSFUL_TOKEN_RESPONSE_RECEIVED));
        }

        @Test
        void shouldRedirectToFrontendErrorPageIfUnsuccessfulResponseReceivedFromUserInfoEndpoint() {
            authExternalApiStub.register(
                    "/userinfo", 400, "application/json", "{\"error\": \"invalid_request\"}");

            var response =
                    makeRequest(
                            Optional.empty(),
                            constructHeaders(
                                    Optional.of(buildSessionCookie(SESSION_ID, CLIENT_SESSION_ID))),
                            constructQueryStringParameters());

            assertThat(response, hasStatus(302));
            assertThat(
                    response.getHeaders().get(ResponseHeaders.LOCATION),
                    startsWith(TEST_CONFIGURATION_SERVICE.getLoginURI().toString()));
            assertThat(response.getHeaders().get(ResponseHeaders.LOCATION), endsWith("error"));

            assertTxmaAuditEventsReceived(
                    txmaAuditQueue,
                    List.of(
                            OrchestrationAuditableEvent.AUTH_CALLBACK_RESPONSE_RECEIVED,
                            OrchestrationAuditableEvent.AUTH_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED,
                            OrchestrationAuditableEvent
                                    .AUTH_UNSUCCESSFUL_USERINFO_RESPONSE_RECEIVED));
        }

        private void setupClientRegWithoutIdentityVerificationSupported() {
            setupClientReg(false);
        }
    }

    @Nested
    class IPVJourney {

        @BeforeEach()
        void ipvSetup() throws Json.JsonException {
            setupTest();
            setupSession();
            setupClientRegWithIdentityVerificationSupported();
        }

        @Test
        void shouldRedirectToIPVWhenIdentityRequired() throws Json.JsonException {
            var response =
                    makeRequest(
                            Optional.empty(),
                            constructHeaders(
                                    Optional.of(buildSessionCookie(SESSION_ID, CLIENT_SESSION_ID))),
                            constructQueryStringParameters());

            assertThat(response, hasStatus(302));

            URI redirectLocationHeader =
                    URI.create(response.getHeaders().get(ResponseHeaders.LOCATION));

            assertThat(
                    redirectLocationHeader.toString(),
                    startsWith(configurationService.getIPVAuthorisationURI().toString()));

            assertTxmaAuditEventsReceived(
                    txmaAuditQueue,
                    List.of(
                            OrchestrationAuditableEvent.AUTH_CALLBACK_RESPONSE_RECEIVED,
                            OrchestrationAuditableEvent.AUTH_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED,
                            OrchestrationAuditableEvent.AUTH_SUCCESSFUL_USERINFO_RESPONSE_RECEIVED,
                            IPVAuditableEvent.IPV_AUTHORISATION_REQUESTED));
        }

        private void setupClientRegWithIdentityVerificationSupported() {
            setupClientReg(true);
        }
    }

    private void setupClientReg(boolean identityVerificationSupport) {
        clientStore.registerClient(
                CLIENT_ID,
                "test-client",
                singletonList(REDIRECT_URI.toString()),
                singletonList("contact@example.com"),
                singletonList("openid"),
                null,
                singletonList("http://localhost/post-redirect-logout"),
                "http://example.com",
                String.valueOf(ServiceType.MANDATORY),
                "https://test.com",
                "pairwise",
                true,
                ClientType.APP,
                identityVerificationSupport);
    }

    private void setupTest() {
        handler = new AuthenticationCallbackHandler(configurationService);
        authExternalApiStub.init(SUBJECT_ID);
        txmaAuditQueue.clear();
    }

    private void setupSession() throws Json.JsonException {
        String vtrStr =
                LevelOfConfidence.MEDIUM_LEVEL.getValue()
                        + "."
                        + CredentialTrustLevel.MEDIUM_LEVEL.getValue();
        VectorOfTrust vot =
                VectorOfTrust.parseFromAuthRequestAttribute(Arrays.asList("[\"" + vtrStr + "\"]"));

        var authRequestBuilder =
                new AuthenticationRequest.Builder(
                                ResponseType.CODE, SCOPE, new ClientID(CLIENT_ID), REDIRECT_URI)
                        .state(RP_STATE)
                        .nonce(new Nonce())
                        .customParameter("vtr", jsonArrayOf(vtrStr));
        redis.createSession(SESSION_ID);
        var clientSession =
                new ClientSession(
                        authRequestBuilder.build().toParameters(),
                        LocalDateTime.now(),
                        vot,
                        CLIENT_NAME);

        redis.createClientSession(CLIENT_SESSION_ID, clientSession);
        redis.addStateToRedis(
                AuthenticationAuthorizationService.AUTHENTICATION_STATE_STORAGE_PREFIX,
                ORCH_TO_AUTH_STATE,
                SESSION_ID);
    }

    private Map<String, String> constructQueryStringParameters() {
        final Map<String, String> queryStringParameters = new HashMap<>();
        queryStringParameters.putAll(
                Map.of(
                        "state",
                        ORCH_TO_AUTH_STATE.getValue(),
                        "code",
                        new AuthorizationCode().getValue()));
        return queryStringParameters;
    }

    private static KeyPair generateRsaKeyPair() {
        KeyPairGenerator kpg;
        try {
            kpg = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    protected static class TestConfigurationService extends IntegrationTestConfigurationService {

        private final AuthExternalApiStubExtension authExternalApiStub;

        public TestConfigurationService(
                AuthExternalApiStubExtension authExternalApiStub,
                SnsTopicExtension auditEventTopic,
                SqsQueueExtension notificationQueue,
                KmsKeyExtension auditSigningKey,
                TokenSigningExtension tokenSigningKey,
                TokenSigningExtension ipvPrivateKeyJwtSigner,
                SqsQueueExtension spotQueue,
                TokenSigningExtension docAppPrivateKeyJwtSigner) {
            super(
                    auditEventTopic,
                    notificationQueue,
                    auditSigningKey,
                    tokenSigningKey,
                    ipvPrivateKeyJwtSigner,
                    spotQueue,
                    docAppPrivateKeyJwtSigner,
                    configurationParameters);
            this.authExternalApiStub = authExternalApiStub;
        }

        @Override
        public URI getAuthenticationBackendURI() {
            try {
                return new URIBuilder()
                        .setHost("localhost")
                        .setPort(authExternalApiStub.getHttpPort())
                        .setScheme("http")
                        .build();
            } catch (URISyntaxException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public String getOrchestrationClientId() {
            return CLIENT_ID;
        }

        @Override
        public URI getAuthenticationAuthCallbackURI() {
            return URI.create("http://localhost/redirect");
        }

        @Override
        public String getTxmaAuditQueueUrl() {
            return txmaAuditQueue.getQueueUrl();
        }

        @Override
        public String getOrchestrationToAuthenticationTokenSigningKeyAlias() {
            return orchestrationPrivateKeyJwtSigner.getKeyAlias();
        }

        @Override
        public boolean isIdentityEnabled() {
            return true;
        }

        @Override
        public String getIPVAuthorisationClientId() {
            return IPV_CLIENT_ID;
        }

        @Override
        public String getIPVAuthEncryptionPublicKey() {
            return publicKey;
        }
    }
}

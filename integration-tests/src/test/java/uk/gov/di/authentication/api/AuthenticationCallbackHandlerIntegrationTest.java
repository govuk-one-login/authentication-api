package uk.gov.di.authentication.api;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
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
import uk.gov.di.authentication.oidc.lambda.AuthenticationCallbackHandler;
import uk.gov.di.authentication.oidc.services.AuthenticationAuthorizationService;
import uk.gov.di.authentication.sharedtest.extensions.AccountInterventionsStubExtension;
import uk.gov.di.orchestration.shared.domain.AccountInterventionsAuditableEvent;
import uk.gov.di.orchestration.shared.domain.LogoutAuditableEvent;
import uk.gov.di.orchestration.shared.entity.AuthenticationUserInfo;
import uk.gov.di.orchestration.shared.entity.ClientSession;
import uk.gov.di.orchestration.shared.entity.ClientType;
import uk.gov.di.orchestration.shared.entity.CredentialTrustLevel;
import uk.gov.di.orchestration.shared.entity.LevelOfConfidence;
import uk.gov.di.orchestration.shared.entity.ResponseHeaders;
import uk.gov.di.orchestration.shared.entity.ServiceType;
import uk.gov.di.orchestration.shared.entity.VectorOfTrust;
import uk.gov.di.orchestration.shared.exceptions.AccountInterventionException;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.orchestration.sharedtest.extensions.AuthExternalApiStubExtension;
import uk.gov.di.orchestration.sharedtest.extensions.AuthenticationCallbackUserInfoStoreExtension;
import uk.gov.di.orchestration.sharedtest.extensions.KmsKeyExtension;
import uk.gov.di.orchestration.sharedtest.extensions.SnsTopicExtension;
import uk.gov.di.orchestration.sharedtest.extensions.SqsQueueExtension;
import uk.gov.di.orchestration.sharedtest.extensions.TokenSigningExtension;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import static com.nimbusds.jose.JWSAlgorithm.ES256;
import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.endsWith;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.matchesPattern;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.orchestration.shared.entity.VectorOfTrust.parseFromAuthRequestAttribute;
import static uk.gov.di.orchestration.sharedtest.helper.AuditAssertionsHelper.assertTxmaAuditEventsReceived;
import static uk.gov.di.orchestration.sharedtest.helper.JsonArrayHelper.jsonArrayOf;
import static uk.gov.di.orchestration.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

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

    @RegisterExtension
    public final AccountInterventionsStubExtension accountInterventionApiStub =
            new AccountInterventionsStubExtension();

    protected ConfigurationService configurationService;

    private static final String CLIENT_ID = "test-client-id";
    private static final String CLIENT_NAME = "test-client-name";
    private static final URI REDIRECT_URI = URI.create("http://localhost/redirect");
    private static final Subject SUBJECT_ID = new Subject();
    private static final String IPV_CLIENT_ID = "ipv-client-id";
    private static final String TEST_EMAIL_ADDRESS = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final KeyPair keyPair = generateRsaKeyPair();
    private static final String publicKey =
            "-----BEGIN PUBLIC KEY-----\n"
                    + Base64.getMimeEncoder().encodeToString(keyPair.getPublic().getEncoded())
                    + "\n-----END PUBLIC KEY-----\n";

    @Nested
    class AuthOnlyJourney {

        @BeforeEach()
        void authSetup() throws Json.JsonException {
            setupTestWithDefaultEnvVars();
            setupSession();
            setupClientRegWithoutIdentityVerificationSupported();
            accountInterventionApiStub.initWithAccountStatus(
                    SUBJECT_ID.getValue(), false, false, false, false);
        }

        @Test
        void shouldStoreUserInfoAndRedirectToRpWhenSuccessfullyProcessedCallbackResponse() {
            var response =
                    makeRequest(
                            Optional.empty(),
                            constructHeaders(
                                    Optional.of(buildSessionCookie(SESSION_ID, CLIENT_SESSION_ID))),
                            constructQueryStringParameters());

            assertUserInfoStoredAndRedirectedToRp(response);
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
    class IdentityJourney {

        @BeforeEach()
        void ipvSetup() throws Json.JsonException {
            setupTestWithDefaultEnvVars();
            setupSession();
            setupClientRegWithIdentityVerificationSupported();
            accountInterventionApiStub.initWithAccountStatus(
                    SUBJECT_ID.getValue(), false, false, false, false);
        }

        @Test
        void shouldRedirectToIPVWhenIdentityRequired()
                throws ParseException, JOSEException, java.text.ParseException {
            var response =
                    makeRequest(
                            Optional.empty(),
                            constructHeaders(
                                    Optional.of(buildSessionCookie(SESSION_ID, CLIENT_SESSION_ID))),
                            constructQueryStringParameters());

            assertRedirectToIpv(response, false);
        }
    }

    @Nested
    class AccountInterventionsAuthOnlyJourney {

        @BeforeEach()
        void accountInterventionSetup() throws Json.JsonException {
            setupSession();
            setupClientRegWithoutIdentityVerificationSupported();
        }

        @Test
        void shouldRedirectToRpWhenAccountStatusIsNoIntervention() throws Json.JsonException {
            setupTestWithDefaultEnvVars();
            accountInterventionApiStub.initWithAccountStatus(
                    SUBJECT_ID.getValue(), false, false, false, false);

            var session = redis.getSession(SESSION_ID);
            assertNotNull(session);

            var response =
                    makeRequest(
                            Optional.of(TEST_EMAIL_ADDRESS),
                            constructHeaders(
                                    Optional.of(buildSessionCookie(SESSION_ID, CLIENT_SESSION_ID))),
                            constructQueryStringParameters());

            assertUserInfoStoredAndRedirectedToRp(response);
        }

        @Test
        void shouldLogoutAndRedirectToBlockedPageWhenAccountStatusIsBlocked()
                throws Json.JsonException {
            setupTestWithDefaultEnvVars();
            accountInterventionApiStub.initWithAccountStatus(
                    SUBJECT_ID.getValue(), true, false, false, false);

            var session = redis.getSession(SESSION_ID);
            assertNotNull(session);

            var response =
                    makeRequest(
                            Optional.of(TEST_EMAIL_ADDRESS),
                            constructHeaders(
                                    Optional.of(buildSessionCookie(SESSION_ID, CLIENT_SESSION_ID))),
                            constructQueryStringParameters());

            assertRedirectToBlockedPage(response);
        }

        @Test
        void shouldLogoutAndRedirectToSuspendedPageWhenAccountStatusIsSuspendedNoAction()
                throws Json.JsonException {
            setupTestWithDefaultEnvVars();
            accountInterventionApiStub.initWithAccountStatus(
                    SUBJECT_ID.getValue(), false, true, false, false);

            var session = redis.getSession(SESSION_ID);
            assertNotNull(session);

            var response =
                    makeRequest(
                            Optional.of(TEST_EMAIL_ADDRESS),
                            constructHeaders(
                                    Optional.of(buildSessionCookie(SESSION_ID, CLIENT_SESSION_ID))),
                            constructQueryStringParameters());

            assertRedirectToSuspendedPage(response);
        }

        @Test
        void shouldLogoutAndRedirectToSuspendedPageWhenAccountStatusIsSuspendedResetPassword()
                throws Json.JsonException {
            setupTestWithDefaultEnvVars();
            accountInterventionApiStub.initWithAccountStatus(
                    SUBJECT_ID.getValue(), false, true, false, true);

            var session = redis.getSession(SESSION_ID);
            assertNotNull(session);

            var response =
                    makeRequest(
                            Optional.of(TEST_EMAIL_ADDRESS),
                            constructHeaders(
                                    Optional.of(buildSessionCookie(SESSION_ID, CLIENT_SESSION_ID))),
                            constructQueryStringParameters());

            assertRedirectToSuspendedPage(response);
        }

        @Test
        void shouldRedirectToRpWhenAccountStatusIsSuspendedReproveIdentity()
                throws Json.JsonException {
            setupTestWithDefaultEnvVars();
            accountInterventionApiStub.initWithAccountStatus(
                    SUBJECT_ID.getValue(), false, true, true, false);

            var session = redis.getSession(SESSION_ID);
            assertNotNull(session);

            var response =
                    makeRequest(
                            Optional.of(TEST_EMAIL_ADDRESS),
                            constructHeaders(
                                    Optional.of(buildSessionCookie(SESSION_ID, CLIENT_SESSION_ID))),
                            constructQueryStringParameters());

            assertUserInfoStoredAndRedirectedToRp(response);
        }

        @Test
        void
                shouldLogoutAndRedirectToSuspendedPageWhenAccountStatusIsSuspendedResetPasswordReproveIdentity()
                        throws Json.JsonException {
            setupTestWithDefaultEnvVars();
            accountInterventionApiStub.initWithAccountStatus(
                    SUBJECT_ID.getValue(), false, true, true, true);

            var session = redis.getSession(SESSION_ID);
            assertNotNull(session);

            var response =
                    makeRequest(
                            Optional.of(TEST_EMAIL_ADDRESS),
                            constructHeaders(
                                    Optional.of(buildSessionCookie(SESSION_ID, CLIENT_SESSION_ID))),
                            constructQueryStringParameters());

            assertRedirectToSuspendedPage(response);
        }

        @Test
        void
                shouldRedirectToRpWhenAccountStatusIsSuspendedResetPasswordAndPasswordWasResetAfterInterventionWasApplied()
                        throws Json.JsonException {
            setupTestWithDefaultEnvVars();
            authExternalApiStub.init(SUBJECT_ID, Long.MAX_VALUE);
            accountInterventionApiStub.initWithAccountStatus(
                    SUBJECT_ID.getValue(), false, true, false, true);

            var session = redis.getSession(SESSION_ID);
            assertNotNull(session);

            var response =
                    makeRequest(
                            Optional.of(TEST_EMAIL_ADDRESS),
                            constructHeaders(
                                    Optional.of(buildSessionCookie(SESSION_ID, CLIENT_SESSION_ID))),
                            constructQueryStringParameters());

            assertUserInfoStoredAndRedirectedToRp(response);
        }

        @Test
        void
                shouldRedirectToRpWhenAccountStatusIsSuspendedResetPasswordReproveIdentityAndPasswordWasResetAfterInterventionWasApplied()
                        throws Json.JsonException {
            setupTestWithDefaultEnvVars();
            authExternalApiStub.init(SUBJECT_ID, Long.MAX_VALUE);
            accountInterventionApiStub.initWithAccountStatus(
                    SUBJECT_ID.getValue(), false, true, true, true);

            var session = redis.getSession(SESSION_ID);
            assertNotNull(session);

            var response =
                    makeRequest(
                            Optional.of(TEST_EMAIL_ADDRESS),
                            constructHeaders(
                                    Optional.of(buildSessionCookie(SESSION_ID, CLIENT_SESSION_ID))),
                            constructQueryStringParameters());

            assertUserInfoStoredAndRedirectedToRp(response);
        }

        @Test
        void byDefaultDoesNotThrowWhenAisReturns500() throws Json.JsonException {
            setupTestWithDefaultEnvVars();
            accountInterventionApiStub.initWithErrorResponse(SUBJECT_ID.getValue());

            var session = redis.getSession(SESSION_ID);
            assertNotNull(session);

            assertDoesNotThrow(
                    () ->
                            makeRequest(
                                    Optional.of(TEST_EMAIL_ADDRESS),
                                    constructHeaders(
                                            Optional.of(
                                                    buildSessionCookie(
                                                            SESSION_ID, CLIENT_SESSION_ID))),
                                    constructQueryStringParameters()));
        }

        @Test
        void doesThrowWhenAisReturns500AndAbortFlagIsOn() throws Json.JsonException {
            setupTestWithAbortOnAisErrorResponseFlagOn();
            accountInterventionApiStub.initWithErrorResponse(SUBJECT_ID.getValue());

            var session = redis.getSession(SESSION_ID);
            assertNotNull(session);

            assertThrows(
                    AccountInterventionException.class,
                    () ->
                            makeRequest(
                                    Optional.of(TEST_EMAIL_ADDRESS),
                                    constructHeaders(
                                            Optional.of(
                                                    buildSessionCookie(
                                                            SESSION_ID, CLIENT_SESSION_ID))),
                                    constructQueryStringParameters()));
        }

        @Test
        void shouldRedirectToRpWhenFieldsAreMissingInResponse() throws Json.JsonException {
            setupTestWithDefaultEnvVars();
            accountInterventionApiStub.initWithoutOptionalFields(
                    SUBJECT_ID.getValue(), false, false, false, false);

            var session = redis.getSession(SESSION_ID);
            assertNotNull(session);

            var response =
                    makeRequest(
                            Optional.of(TEST_EMAIL_ADDRESS),
                            constructHeaders(
                                    Optional.of(buildSessionCookie(SESSION_ID, CLIENT_SESSION_ID))),
                            constructQueryStringParameters());

            assertUserInfoStoredAndRedirectedToRp(response);
        }
    }

    @Nested
    class AccountInterventionsIdentityJourney {

        @BeforeEach()
        void accountInterventionSetup() throws Json.JsonException {
            setupSession();
            setupClientRegWithIdentityVerificationSupported();
        }

        @Test
        void shouldRedirectToIpvWhenAccountStatusIsNoIntervention()
                throws Json.JsonException, java.text.ParseException, ParseException, JOSEException {
            setupTestWithDefaultEnvVars();
            accountInterventionApiStub.initWithAccountStatus(
                    SUBJECT_ID.getValue(), false, false, false, false);

            var session = redis.getSession(SESSION_ID);
            assertNotNull(session);

            var response =
                    makeRequest(
                            Optional.of(TEST_EMAIL_ADDRESS),
                            constructHeaders(
                                    Optional.of(buildSessionCookie(SESSION_ID, CLIENT_SESSION_ID))),
                            constructQueryStringParameters());

            assertRedirectToIpv(response, false);
        }

        @Test
        void shouldLogoutAndRedirectToBlockedPageWhenAccountStatusIsBlocked()
                throws Json.JsonException {
            setupTestWithDefaultEnvVars();
            accountInterventionApiStub.initWithAccountStatus(
                    SUBJECT_ID.getValue(), true, false, false, false);

            var session = redis.getSession(SESSION_ID);
            assertNotNull(session);

            var response =
                    makeRequest(
                            Optional.of(TEST_EMAIL_ADDRESS),
                            constructHeaders(
                                    Optional.of(buildSessionCookie(SESSION_ID, CLIENT_SESSION_ID))),
                            constructQueryStringParameters());

            assertRedirectToBlockedPage(response);
        }

        @Test
        void shouldRedirectToIpvpWhenAccountStatusIsSuspendedNoAction()
                throws Json.JsonException, java.text.ParseException, ParseException, JOSEException {
            setupTestWithDefaultEnvVars();
            accountInterventionApiStub.initWithAccountStatus(
                    SUBJECT_ID.getValue(), false, false, false, false);

            var session = redis.getSession(SESSION_ID);
            assertNotNull(session);

            var response =
                    makeRequest(
                            Optional.of(TEST_EMAIL_ADDRESS),
                            constructHeaders(
                                    Optional.of(buildSessionCookie(SESSION_ID, CLIENT_SESSION_ID))),
                            constructQueryStringParameters());

            assertRedirectToIpv(response, false);
        }

        @Test
        void shouldLogoutAndRedirectToSuspendedPageWhenAccountStatusIsSuspendedResetPassword()
                throws Json.JsonException {
            setupTestWithDefaultEnvVars();
            accountInterventionApiStub.initWithAccountStatus(
                    SUBJECT_ID.getValue(), false, true, false, true);

            var session = redis.getSession(SESSION_ID);
            assertNotNull(session);

            var response =
                    makeRequest(
                            Optional.of(TEST_EMAIL_ADDRESS),
                            constructHeaders(
                                    Optional.of(buildSessionCookie(SESSION_ID, CLIENT_SESSION_ID))),
                            constructQueryStringParameters());

            assertRedirectToSuspendedPage(response);
        }

        @Test
        void shouldRedirectToIpvWhenAccountStatusIsSuspendedReproveIdentity()
                throws Json.JsonException, java.text.ParseException, ParseException, JOSEException {
            setupTestWithDefaultEnvVars();
            accountInterventionApiStub.initWithAccountStatus(
                    SUBJECT_ID.getValue(), false, true, true, false);

            var session = redis.getSession(SESSION_ID);
            assertNotNull(session);

            var response =
                    makeRequest(
                            Optional.of(TEST_EMAIL_ADDRESS),
                            constructHeaders(
                                    Optional.of(buildSessionCookie(SESSION_ID, CLIENT_SESSION_ID))),
                            constructQueryStringParameters());

            assertRedirectToIpv(response, true);
        }

        @Test
        void
                shouldLogoutAndRedirectToSuspendedPageWhenAccountStatusIsSuspendedResetPasswordReproveIdentity()
                        throws Json.JsonException {
            setupTestWithDefaultEnvVars();
            accountInterventionApiStub.initWithAccountStatus(
                    SUBJECT_ID.getValue(), false, true, false, true);

            var session = redis.getSession(SESSION_ID);
            assertNotNull(session);

            var response =
                    makeRequest(
                            Optional.of(TEST_EMAIL_ADDRESS),
                            constructHeaders(
                                    Optional.of(buildSessionCookie(SESSION_ID, CLIENT_SESSION_ID))),
                            constructQueryStringParameters());

            assertRedirectToSuspendedPage(response);
        }

        @Test
        void
                shouldRedirectToIpvWhenAccountStatusIsSuspendedResetPasswordAndPasswordWasResetAfterInterventionWasApplied()
                        throws Json.JsonException,
                                java.text.ParseException,
                                ParseException,
                                JOSEException {
            setupTestWithDefaultEnvVars();
            authExternalApiStub.init(SUBJECT_ID, Long.MAX_VALUE);
            accountInterventionApiStub.initWithAccountStatus(
                    SUBJECT_ID.getValue(), false, true, false, true);

            var session = redis.getSession(SESSION_ID);
            assertNotNull(session);

            var response =
                    makeRequest(
                            Optional.of(TEST_EMAIL_ADDRESS),
                            constructHeaders(
                                    Optional.of(buildSessionCookie(SESSION_ID, CLIENT_SESSION_ID))),
                            constructQueryStringParameters());

            assertRedirectToIpv(response, false);
        }

        @Test
        void
                shouldRedirectToIpvWhenAccountStatusIsSuspendedResetPasswordReproveIdentityAndPasswordWasResetAfterInterventionWasApplied()
                        throws Json.JsonException,
                                java.text.ParseException,
                                ParseException,
                                JOSEException {
            setupTestWithDefaultEnvVars();
            authExternalApiStub.init(SUBJECT_ID, Long.MAX_VALUE);
            accountInterventionApiStub.initWithAccountStatus(
                    SUBJECT_ID.getValue(), false, true, true, true);

            var session = redis.getSession(SESSION_ID);
            assertNotNull(session);

            var response =
                    makeRequest(
                            Optional.of(TEST_EMAIL_ADDRESS),
                            constructHeaders(
                                    Optional.of(buildSessionCookie(SESSION_ID, CLIENT_SESSION_ID))),
                            constructQueryStringParameters());

            assertRedirectToIpv(response, true);
        }

        @Test
        void byDefaultDoesNotThrowWhenAisReturns500() throws Json.JsonException {
            setupTestWithDefaultEnvVars();
            accountInterventionApiStub.initWithErrorResponse(SUBJECT_ID.getValue());

            var session = redis.getSession(SESSION_ID);
            assertNotNull(session);

            assertDoesNotThrow(
                    () ->
                            makeRequest(
                                    Optional.of(TEST_EMAIL_ADDRESS),
                                    constructHeaders(
                                            Optional.of(
                                                    buildSessionCookie(
                                                            SESSION_ID, CLIENT_SESSION_ID))),
                                    constructQueryStringParameters()));
        }

        @Test
        void doesThrowWhenAisReturns500AndAbortFlagIsOn() throws Json.JsonException {
            setupTestWithAbortOnAisErrorResponseFlagOn();
            accountInterventionApiStub.initWithErrorResponse(SUBJECT_ID.getValue());

            var session = redis.getSession(SESSION_ID);
            assertNotNull(session);

            assertThrows(
                    AccountInterventionException.class,
                    () ->
                            makeRequest(
                                    Optional.of(TEST_EMAIL_ADDRESS),
                                    constructHeaders(
                                            Optional.of(
                                                    buildSessionCookie(
                                                            SESSION_ID, CLIENT_SESSION_ID))),
                                    constructQueryStringParameters()));
        }
    }

    private void assertRedirectToSuspendedPage(APIGatewayProxyResponseEvent response) {
        assertThat(response, hasStatus(302));
        assertThrows(
                uk.gov.di.orchestration.shared.serialization.Json.JsonException.class,
                () -> redis.getSession(SESSION_ID));

        URI redirectLocationHeader =
                URI.create(response.getHeaders().get(ResponseHeaders.LOCATION));

        assertThat(
                redirectLocationHeader.toString(),
                containsString(configurationService.getAccountStatusSuspendedURI().toString()));

        assertTxmaAuditEventsReceived(
                txmaAuditQueue,
                List.of(
                        OrchestrationAuditableEvent.AUTH_CALLBACK_RESPONSE_RECEIVED,
                        AccountInterventionsAuditableEvent.AIS_RESPONSE_RECEIVED,
                        OrchestrationAuditableEvent.AUTH_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED,
                        OrchestrationAuditableEvent.AUTH_SUCCESSFUL_USERINFO_RESPONSE_RECEIVED,
                        OidcAuditableEvent.AUTHENTICATION_COMPLETE,
                        LogoutAuditableEvent.LOG_OUT_SUCCESS));
    }

    private void assertRedirectToBlockedPage(APIGatewayProxyResponseEvent response) {
        assertThat(response, hasStatus(302));
        assertThrows(
                uk.gov.di.orchestration.shared.serialization.Json.JsonException.class,
                () -> redis.getSession(SESSION_ID));

        URI redirectLocationHeader =
                URI.create(response.getHeaders().get(ResponseHeaders.LOCATION));

        assertThat(
                redirectLocationHeader.toString(),
                containsString(configurationService.getAccountStatusBlockedURI().toString()));

        assertTxmaAuditEventsReceived(
                txmaAuditQueue,
                List.of(
                        OrchestrationAuditableEvent.AUTH_CALLBACK_RESPONSE_RECEIVED,
                        AccountInterventionsAuditableEvent.AIS_RESPONSE_RECEIVED,
                        OrchestrationAuditableEvent.AUTH_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED,
                        OrchestrationAuditableEvent.AUTH_SUCCESSFUL_USERINFO_RESPONSE_RECEIVED,
                        OidcAuditableEvent.AUTHENTICATION_COMPLETE,
                        LogoutAuditableEvent.LOG_OUT_SUCCESS));
    }

    private void assertRedirectToIpv(APIGatewayProxyResponseEvent response, boolean reproveIdentity)
            throws java.text.ParseException, JOSEException, ParseException {
        var authRequest = validateQueryRequestToIPVAndReturnAuthRequest(response);

        var encryptedRequestObject = authRequest.getRequestObject();
        var signedJWTResponse = decryptJWT((EncryptedJWT) encryptedRequestObject);

        validateClaimsInJar(signedJWTResponse, reproveIdentity);

        assertTxmaAuditEventsReceived(
                txmaAuditQueue,
                List.of(
                        OrchestrationAuditableEvent.AUTH_CALLBACK_RESPONSE_RECEIVED,
                        AccountInterventionsAuditableEvent.AIS_RESPONSE_RECEIVED,
                        OrchestrationAuditableEvent.AUTH_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED,
                        OrchestrationAuditableEvent.AUTH_SUCCESSFUL_USERINFO_RESPONSE_RECEIVED,
                        OidcAuditableEvent.AUTHENTICATION_COMPLETE,
                        IPVAuditableEvent.IPV_AUTHORISATION_REQUESTED));
    }

    private void assertUserInfoStoredAndRedirectedToRp(APIGatewayProxyResponseEvent response) {
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
                        AccountInterventionsAuditableEvent.AIS_RESPONSE_RECEIVED,
                        OidcAuditableEvent.AUTHENTICATION_COMPLETE,
                        OidcAuditableEvent.AUTH_CODE_ISSUED));

        Optional<AuthenticationUserInfo> userInfoDbEntry =
                userInfoStoreExtension.getUserInfoBySubjectId(SUBJECT_ID.getValue());
        assertTrue(userInfoDbEntry.isPresent());
        assertEquals(SUBJECT_ID.getValue(), userInfoDbEntry.get().getSubjectID());
        assertThat(userInfoDbEntry.get().getUserInfo(), containsString("new_account"));
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
                ClientType.APP,
                ES256.getName(),
                identityVerificationSupport);
    }

    private void setupClientRegWithIdentityVerificationSupported() {
        setupClientReg(true);
    }

    private void setupClientRegWithoutIdentityVerificationSupported() {
        setupClientReg(false);
    }

    private void setupTestWithDefaultEnvVars() {
        setupTest(false);
    }

    private void setupTestWithAbortOnAisErrorResponseFlagOn() {
        setupTest(true);
    }

    private void setupTest(boolean abortOnAisErrorResponse) {
        configurationService =
                new AuthenticationCallbackHandlerIntegrationTest.TestConfigurationService(
                        authExternalApiStub,
                        auditTopic,
                        notificationsQueue,
                        auditSigningKey,
                        externalTokenSigner,
                        ipvPrivateKeyJwtSigner,
                        spotQueue,
                        docAppPrivateKeyJwtSigner,
                        accountInterventionApiStub,
                        abortOnAisErrorResponse);
        handler = new AuthenticationCallbackHandler(configurationService);
        authExternalApiStub.init(SUBJECT_ID);
        txmaAuditQueue.clear();
    }

    private void setupSession() throws Json.JsonException {
        redis.createSession(SESSION_ID);
        redis.addStateToRedis(
                AuthenticationAuthorizationService.AUTHENTICATION_STATE_STORAGE_PREFIX,
                ORCH_TO_AUTH_STATE,
                SESSION_ID);
        setUpClientSession();
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
        private final AccountInterventionsStubExtension accountInterventionApiStub;
        private final boolean abortOnAisErrorResponse;

        public TestConfigurationService(
                AuthExternalApiStubExtension authExternalApiStub,
                SnsTopicExtension auditEventTopic,
                SqsQueueExtension notificationQueue,
                KmsKeyExtension auditSigningKey,
                TokenSigningExtension tokenSigningKey,
                TokenSigningExtension ipvPrivateKeyJwtSigner,
                SqsQueueExtension spotQueue,
                TokenSigningExtension docAppPrivateKeyJwtSigner,
                AccountInterventionsStubExtension accountInterventionsStubExtension,
                boolean abortOnAisErrorResponse) {
            super(
                    tokenSigningKey,
                    storageTokenSigner,
                    ipvPrivateKeyJwtSigner,
                    spotQueue,
                    docAppPrivateKeyJwtSigner,
                    configurationParameters);
            this.authExternalApiStub = authExternalApiStub;
            this.accountInterventionApiStub = accountInterventionsStubExtension;
            this.abortOnAisErrorResponse = abortOnAisErrorResponse;
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
        public URI getIPVAuthorisationURI() {
            return URI.create("https://ipv.gov.uk/authorize");
        }

        @Override
        public String getIPVAuthorisationClientId() {
            return IPV_CLIENT_ID;
        }

        @Override
        public String getIPVAuthEncryptionPublicKey() {
            return publicKey;
        }

        @Override
        public URI getAccountInterventionServiceURI() {
            try {
                return new URIBuilder()
                        .setHost("localhost")
                        .setPort(accountInterventionApiStub.getHttpPort())
                        .setScheme("http")
                        .build();
            } catch (URISyntaxException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public boolean isAccountInterventionServiceCallEnabled() {
            return true;
        }

        @Override
        public boolean isAccountInterventionServiceActionEnabled() {
            return true;
        }

        @Override
        public boolean abortOnAccountInterventionsErrorResponse() {
            return this.abortOnAisErrorResponse;
        }
    }

    private void setUpClientSession() throws Json.JsonException {
        String vtrStr1 =
                LevelOfConfidence.MEDIUM_LEVEL.getValue()
                        + "."
                        + CredentialTrustLevel.MEDIUM_LEVEL.getValue();
        String vtrStr2 =
                LevelOfConfidence.HMRC200.getValue()
                        + "."
                        + CredentialTrustLevel.MEDIUM_LEVEL.getValue();

        List<VectorOfTrust> vtrList =
                parseFromAuthRequestAttribute(List.of("[\"" + vtrStr1 + "\",\"" + vtrStr2 + "\"]"));

        var authRequestBuilder =
                new AuthenticationRequest.Builder(
                                ResponseType.CODE, SCOPE, new ClientID(CLIENT_ID), REDIRECT_URI)
                        .state(RP_STATE)
                        .nonce(new Nonce())
                        .customParameter("vtr", jsonArrayOf(vtrStr1, vtrStr2));
        var clientSession =
                new ClientSession(
                        authRequestBuilder.build().toParameters(),
                        LocalDateTime.now(),
                        vtrList,
                        CLIENT_NAME);

        redis.createClientSession(CLIENT_SESSION_ID, clientSession);
    }

    private AuthorizationRequest validateQueryRequestToIPVAndReturnAuthRequest(
            APIGatewayProxyResponseEvent response) throws ParseException {
        assertThat(response, hasStatus(302));
        var expectedQueryStringRegex = "response_type=code&request=.*&client_id=ipv-client-id";
        URI redirectLocationHeader =
                URI.create(response.getHeaders().get(ResponseHeaders.LOCATION));
        assertThat(
                redirectLocationHeader.toString(),
                startsWith(configurationService.getIPVAuthorisationURI().toString()));
        assertThat(redirectLocationHeader.getQuery(), matchesPattern(expectedQueryStringRegex));

        var authorisationRequest = AuthorizationRequest.parse(redirectLocationHeader);
        assertThat(authorisationRequest.getClientID().getValue(), equalTo(IPV_CLIENT_ID));
        assertThat(authorisationRequest.getResponseType(), equalTo(ResponseType.CODE));
        assertTrue(Objects.nonNull(authorisationRequest.getRequestObject()));
        return authorisationRequest;
    }

    private SignedJWT decryptJWT(EncryptedJWT encryptedJWT) throws JOSEException {
        encryptedJWT.decrypt(new RSADecrypter(keyPair.getPrivate()));
        return encryptedJWT.getPayload().toSignedJWT();
    }

    private void validateClaimsInJar(SignedJWT signedJWT, boolean reproveIdentity)
            throws java.text.ParseException {
        assertTrue(Objects.nonNull(signedJWT.getJWTClaimsSet().getClaim("sub")));
        assertTrue(Objects.nonNull(signedJWT.getJWTClaimsSet().getClaim("iss")));
        assertTrue(Objects.nonNull(signedJWT.getJWTClaimsSet().getClaim("response_type")));
        assertTrue(Objects.nonNull(signedJWT.getJWTClaimsSet().getClaim("reprove_identity")));
        assertTrue(Objects.nonNull(signedJWT.getJWTClaimsSet().getClaim("client_id")));
        assertTrue(
                Objects.nonNull(signedJWT.getJWTClaimsSet().getClaim("govuk_signin_journey_id")));
        assertTrue(Objects.nonNull(signedJWT.getJWTClaimsSet().getClaim("aud")));
        assertTrue(Objects.nonNull(signedJWT.getJWTClaimsSet().getClaim("nbf")));
        assertTrue(Objects.nonNull(signedJWT.getJWTClaimsSet().getClaim("vtr")));
        assertTrue(Objects.nonNull(signedJWT.getJWTClaimsSet().getClaim("scope")));
        assertTrue(Objects.nonNull(signedJWT.getJWTClaimsSet().getClaim("state")));
        assertTrue(Objects.nonNull(signedJWT.getJWTClaimsSet().getClaim("redirect_uri")));
        assertTrue(Objects.nonNull(signedJWT.getJWTClaimsSet().getClaim("exp")));
        assertTrue(Objects.nonNull(signedJWT.getJWTClaimsSet().getClaim("iat")));
        assertTrue(Objects.nonNull(signedJWT.getJWTClaimsSet().getClaim("jti")));

        assertThat(signedJWT.getJWTClaimsSet().getClaim("iss"), equalTo(IPV_CLIENT_ID));
        assertThat(signedJWT.getJWTClaimsSet().getClaim("response_type"), equalTo("code"));
        assertThat(
                (boolean) signedJWT.getJWTClaimsSet().getClaim("reprove_identity"),
                equalTo(reproveIdentity));
        assertThat(signedJWT.getJWTClaimsSet().getClaim("client_id"), equalTo(IPV_CLIENT_ID));
        assertThat(
                signedJWT.getJWTClaimsSet().getClaim("govuk_signin_journey_id"),
                equalTo(CLIENT_SESSION_ID));
        assertThat(signedJWT.getJWTClaimsSet().getClaim("vtr"), equalTo(List.of("P2", "PCL200")));
        assertThat(signedJWT.getJWTClaimsSet().getClaim("scope"), equalTo("openid"));
        assertThat(signedJWT.getHeader().getAlgorithm(), equalTo(ES256));
    }
}

package uk.gov.di.authentication.api;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.apache.http.client.utils.URIBuilder;
import org.junit.jupiter.api.BeforeAll;
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
import uk.gov.di.orchestration.shared.entity.BackChannelLogoutMessage;
import uk.gov.di.orchestration.shared.entity.ClientSession;
import uk.gov.di.orchestration.shared.entity.ClientType;
import uk.gov.di.orchestration.shared.entity.CredentialTrustLevel;
import uk.gov.di.orchestration.shared.entity.LevelOfConfidence;
import uk.gov.di.orchestration.shared.entity.MFAMethodType;
import uk.gov.di.orchestration.shared.entity.OrchClientSessionItem;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem;
import uk.gov.di.orchestration.shared.entity.ResponseHeaders;
import uk.gov.di.orchestration.shared.entity.ServiceType;
import uk.gov.di.orchestration.shared.entity.Session;
import uk.gov.di.orchestration.shared.entity.VectorOfTrust;
import uk.gov.di.orchestration.shared.exceptions.AccountInterventionException;
import uk.gov.di.orchestration.shared.helpers.NowHelper;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.RedisConnectionService;
import uk.gov.di.orchestration.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.orchestration.sharedtest.extensions.AuthExternalApiStubExtension;
import uk.gov.di.orchestration.sharedtest.extensions.AuthenticationCallbackUserInfoStoreExtension;
import uk.gov.di.orchestration.sharedtest.extensions.KmsKeyExtension;
import uk.gov.di.orchestration.sharedtest.extensions.OrchAuthCodeExtension;
import uk.gov.di.orchestration.sharedtest.extensions.OrchClientSessionExtension;
import uk.gov.di.orchestration.sharedtest.extensions.OrchSessionExtension;
import uk.gov.di.orchestration.sharedtest.extensions.SnsTopicExtension;
import uk.gov.di.orchestration.sharedtest.extensions.SqsQueueExtension;
import uk.gov.di.orchestration.sharedtest.extensions.TokenSigningExtension;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import static com.nimbusds.jose.JWSAlgorithm.ES256;
import static java.util.Collections.emptyMap;
import static java.util.Collections.singletonList;
import static org.awaitility.Awaitility.await;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.endsWith;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.matchesPattern;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.oidc.domain.OrchestrationAuditableEvent.AUTH_UNSUCCESSFUL_CALLBACK_RESPONSE_RECEIVED;
import static uk.gov.di.authentication.testsupport.helpers.OrchAuthCodeAssertionHelper.assertOrchAuthCodeSaved;
import static uk.gov.di.orchestration.shared.entity.VectorOfTrust.parseFromAuthRequestAttribute;
import static uk.gov.di.orchestration.shared.helpers.ConstructUriHelper.buildURI;
import static uk.gov.di.orchestration.sharedtest.helper.AuditAssertionsHelper.assertTxmaAuditEventsReceived;
import static uk.gov.di.orchestration.sharedtest.helper.JsonArrayHelper.jsonArrayOf;
import static uk.gov.di.orchestration.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class AuthenticationCallbackHandlerIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    public static final String SESSION_ID = "some-session-id";
    public static final String CLIENT_SESSION_ID = "some-client-session-id";
    public static final Scope SCOPE = new Scope(OIDCScopeValue.OPENID);
    public static final State RP_STATE = new State();
    public static final State ORCH_TO_AUTH_STATE = new State();
    private static final String BLOCKED_ENDPOINT = "unavailable-permanent";
    private static final String SUSPENDED_ENDPOINT = "unavailable-temporary";

    @RegisterExtension
    public static final AuthExternalApiStubExtension authExternalApiStub =
            new AuthExternalApiStubExtension();

    @RegisterExtension
    protected static final AuthenticationCallbackUserInfoStoreExtension userInfoStoreExtension =
            new AuthenticationCallbackUserInfoStoreExtension(180);

    @RegisterExtension
    public static final AccountInterventionsStubExtension accountInterventionApiStub =
            new AccountInterventionsStubExtension();

    @RegisterExtension
    public static final OrchSessionExtension orchSessionExtension = new OrchSessionExtension();

    @RegisterExtension
    public static final OrchClientSessionExtension orchClientSessionExtension =
            new OrchClientSessionExtension();

    @RegisterExtension
    public static final SqsQueueExtension backChannelLogoutQueueExtension =
            new SqsQueueExtension("back-channel-logout-");

    @RegisterExtension
    public static final OrchAuthCodeExtension orchAuthCodeExtension = new OrchAuthCodeExtension();

    protected static ConfigurationService configurationService;

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

    @BeforeAll
    static void beforeAll() {
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
                        false);
        redisConnectionService = new RedisConnectionService(configurationService);
    }

    @BeforeEach()
    void authSetup() throws Json.JsonException {
        setupTestWithDefaultEnvVars();
        setupSession();
        setupClientRegWithoutIdentityVerificationSupported();
        accountInterventionApiStub.initWithAccountStatus(
                SUBJECT_ID.getValue(), false, false, false, false);
    }

    @Test
    void shouldStoreUserInfoAndRedirectToRpWhenSuccessfullyProcessedCallbackResponse()
            throws ParseException {
        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(
                                Optional.of(buildSessionCookie(SESSION_ID, CLIENT_SESSION_ID))),
                        constructQueryStringParameters());

        assertUserInfoStoredAndRedirectedToRp(response);
        assertOrchSessionIsUpdatedWithUserInfoClaims();

        assertOrchAuthCodeSaved(orchAuthCodeExtension, response);
    }

    @Test
    void shouldRedirectToRpWithErrorWhenStateIsInvalid() throws ParseException {
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
                txmaAuditQueue, List.of(AUTH_UNSUCCESSFUL_CALLBACK_RESPONSE_RECEIVED));

        Optional<UserInfo> userInfo =
                userInfoStoreExtension.getAuthenticationUserInfo(
                        SUBJECT_ID.getValue(), CLIENT_SESSION_ID);
        assertTrue(userInfo.isEmpty());
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
                startsWith(TEST_CONFIGURATION_SERVICE.getAuthFrontendBaseURL().toString()));
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
                startsWith(TEST_CONFIGURATION_SERVICE.getAuthFrontendBaseURL().toString()));
        assertThat(response.getHeaders().get(ResponseHeaders.LOCATION), endsWith("error"));

        assertTxmaAuditEventsReceived(
                txmaAuditQueue,
                List.of(
                        OrchestrationAuditableEvent.AUTH_CALLBACK_RESPONSE_RECEIVED,
                        OrchestrationAuditableEvent.AUTH_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED,
                        OrchestrationAuditableEvent.AUTH_UNSUCCESSFUL_USERINFO_RESPONSE_RECEIVED));
    }

    @Test
    void
            shouldRedirectToRPWhenNoSessionCookieAndCallToNoSessionOrchestrationServiceReturnsNoSessionEntity()
                    throws Json.JsonException {
        var scope = new Scope(OIDCScopeValue.OPENID);
        var authRequestBuilder =
                new AuthenticationRequest.Builder(
                                ResponseType.CODE, scope, new ClientID(CLIENT_ID), REDIRECT_URI)
                        .nonce(new Nonce())
                        .state(RP_STATE);
        redis.createClientSession(
                CLIENT_SESSION_ID, CLIENT_NAME, authRequestBuilder.build().toParameters());
        redis.addClientSessionAndStateToRedis(ORCH_TO_AUTH_STATE, CLIENT_SESSION_ID);

        var response =
                makeRequest(
                        Optional.empty(),
                        emptyMap(),
                        new HashMap<>(
                                Map.of(
                                        "state",
                                        ORCH_TO_AUTH_STATE.getValue(),
                                        "error",
                                        "access_denied")));

        var error =
                new ErrorObject(
                        OAuth2Error.ACCESS_DENIED_CODE,
                        "Access denied for security reasons, a new authentication request may be successful");

        var expectedURI =
                new AuthenticationErrorResponse(REDIRECT_URI, error, RP_STATE, null)
                        .toURI()
                        .toString();
        assertThat(response, hasStatus(302));
        assertThat(response.getHeaders().get(ResponseHeaders.LOCATION), equalTo(expectedURI));
        assertTxmaAuditEventsReceived(
                txmaAuditQueue, singletonList(AUTH_UNSUCCESSFUL_CALLBACK_RESPONSE_RECEIVED));
    }

    @Test
    void shouldRedirectToIPVWhenIdentityRequired()
            throws ParseException, JOSEException, java.text.ParseException, Json.JsonException {
        setupTestWithDefaultEnvVars();
        setupSession();
        setupClientRegWithIdentityVerificationSupported();
        accountInterventionApiStub.initWithAccountStatus(
                SUBJECT_ID.getValue(), false, false, false, false);

        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(
                                Optional.of(buildSessionCookie(SESSION_ID, CLIENT_SESSION_ID))),
                        constructQueryStringParameters());

        assertRedirectToIpv(response, false);
        assertOrchSessionIsUpdatedWithUserInfoClaims();
        assertInformationStoredForNoSessionService(response);
    }

    void accountInterventionSetup() throws Json.JsonException {
        setupSession();
        setupClientRegWithoutIdentityVerificationSupported();
    }

    @Test
    void shouldRedirectToRpWhenAccountStatusIsNoIntervention()
            throws Json.JsonException, ParseException {
        accountInterventionSetup();
        setupTestWithDefaultEnvVars();
        accountInterventionApiStub.initWithAccountStatus(
                SUBJECT_ID.getValue(), false, false, false, false);

        var session = redis.getSession(SESSION_ID);
        assertNotNull(session);
        var orchSession = orchSessionExtension.getSession(SESSION_ID);
        assertTrue(orchSession.isPresent());

        var response =
                makeRequest(
                        Optional.of(TEST_EMAIL_ADDRESS),
                        constructHeaders(
                                Optional.of(buildSessionCookie(SESSION_ID, CLIENT_SESSION_ID))),
                        constructQueryStringParameters());

        assertUserInfoStoredAndRedirectedToRp(response);
        assertOrchSessionIsUpdatedWithUserInfoClaims();

        assertOrchAuthCodeSaved(orchAuthCodeExtension, response);
    }

    @Test
    void shouldLogoutAndRedirectToBlockedPageWhenAccountStatusIsBlocked()
            throws Json.JsonException {
        accountInterventionSetup();
        setupTestWithDefaultEnvVars();
        accountInterventionApiStub.initWithAccountStatus(
                SUBJECT_ID.getValue(), true, false, false, false);

        var session = redis.getSession(SESSION_ID);
        assertNotNull(session);
        var orchSession = orchSessionExtension.getSession(SESSION_ID);
        assertTrue(orchSession.isPresent());

        var response =
                makeRequest(
                        Optional.of(TEST_EMAIL_ADDRESS),
                        constructHeaders(
                                Optional.of(buildSessionCookie(SESSION_ID, CLIENT_SESSION_ID))),
                        constructQueryStringParameters());

        assertRedirectToBlockedPage(response);
        assertSessionIsDeleted();
    }

    @Test
    void shouldLogoutAndRedirectToSuspendedPageWhenAccountStatusIsSuspendedNoAction()
            throws Json.JsonException {
        accountInterventionSetup();
        setupTestWithDefaultEnvVars();
        accountInterventionApiStub.initWithAccountStatus(
                SUBJECT_ID.getValue(), false, true, false, false);

        var session = redis.getSession(SESSION_ID);
        assertNotNull(session);
        var orchSession = orchSessionExtension.getSession(SESSION_ID);
        assertTrue(orchSession.isPresent());

        var response =
                makeRequest(
                        Optional.of(TEST_EMAIL_ADDRESS),
                        constructHeaders(
                                Optional.of(buildSessionCookie(SESSION_ID, CLIENT_SESSION_ID))),
                        constructQueryStringParameters());

        assertRedirectToSuspendedPage(response);
        assertSessionIsDeleted();
    }

    @Test
    void shouldLogoutAndRedirectToSuspendedPageWhenAccountStatusIsSuspendedResetPassword()
            throws Json.JsonException {
        accountInterventionSetup();
        setupTestWithDefaultEnvVars();
        accountInterventionApiStub.initWithAccountStatus(
                SUBJECT_ID.getValue(), false, true, false, true);

        var session = redis.getSession(SESSION_ID);
        assertNotNull(session);
        var orchSession = orchSessionExtension.getSession(SESSION_ID);
        assertTrue(orchSession.isPresent());

        var response =
                makeRequest(
                        Optional.of(TEST_EMAIL_ADDRESS),
                        constructHeaders(
                                Optional.of(buildSessionCookie(SESSION_ID, CLIENT_SESSION_ID))),
                        constructQueryStringParameters());

        assertRedirectToSuspendedPage(response);
        assertSessionIsDeleted();
    }

    @Test
    void shouldRedirectToRpWhenAccountStatusIsSuspendedReproveIdentity()
            throws Json.JsonException, ParseException {
        accountInterventionSetup();
        setupTestWithDefaultEnvVars();
        accountInterventionApiStub.initWithAccountStatus(
                SUBJECT_ID.getValue(), false, true, true, false);

        var session = redis.getSession(SESSION_ID);
        assertNotNull(session);
        var orchSession = orchSessionExtension.getSession(SESSION_ID);
        assertTrue(orchSession.isPresent());

        var response =
                makeRequest(
                        Optional.of(TEST_EMAIL_ADDRESS),
                        constructHeaders(
                                Optional.of(buildSessionCookie(SESSION_ID, CLIENT_SESSION_ID))),
                        constructQueryStringParameters());

        assertUserInfoStoredAndRedirectedToRp(response);
        assertOrchSessionIsUpdatedWithUserInfoClaims();

        assertOrchAuthCodeSaved(orchAuthCodeExtension, response);
    }

    @Test
    void
            shouldLogoutAndRedirectToSuspendedPageWhenAccountStatusIsSuspendedResetPasswordReproveIdentity()
                    throws Json.JsonException {
        accountInterventionSetup();
        setupTestWithDefaultEnvVars();
        accountInterventionApiStub.initWithAccountStatus(
                SUBJECT_ID.getValue(), false, true, true, true);

        var session = redis.getSession(SESSION_ID);
        assertNotNull(session);
        var orchSession = orchSessionExtension.getSession(SESSION_ID);
        assertTrue(orchSession.isPresent());

        var response =
                makeRequest(
                        Optional.of(TEST_EMAIL_ADDRESS),
                        constructHeaders(
                                Optional.of(buildSessionCookie(SESSION_ID, CLIENT_SESSION_ID))),
                        constructQueryStringParameters());

        assertRedirectToSuspendedPage(response);
        assertSessionIsDeleted();
    }

    @Test
    void
            shouldRedirectToRpWhenAccountStatusIsSuspendedResetPasswordAndPasswordWasResetAfterInterventionWasApplied()
                    throws Json.JsonException, ParseException {
        accountInterventionSetup();
        setupTestWithDefaultEnvVars();
        authExternalApiStub.init(SUBJECT_ID, Long.MAX_VALUE, false);
        accountInterventionApiStub.initWithAccountStatus(
                SUBJECT_ID.getValue(), false, true, false, true);

        var session = redis.getSession(SESSION_ID);
        assertNotNull(session);
        var orchSession = orchSessionExtension.getSession(SESSION_ID);
        assertTrue(orchSession.isPresent());

        var response =
                makeRequest(
                        Optional.of(TEST_EMAIL_ADDRESS),
                        constructHeaders(
                                Optional.of(buildSessionCookie(SESSION_ID, CLIENT_SESSION_ID))),
                        constructQueryStringParameters());

        assertUserInfoStoredAndRedirectedToRp(response);
        assertOrchSessionIsUpdatedWithUserInfoClaims();

        assertOrchAuthCodeSaved(orchAuthCodeExtension, response);
    }

    @Test
    void
            shouldRedirectToRpWhenAccountStatusIsSuspendedResetPasswordReproveIdentityAndPasswordWasResetAfterInterventionWasApplied()
                    throws Json.JsonException, ParseException {
        accountInterventionSetup();
        setupTestWithDefaultEnvVars();
        authExternalApiStub.init(SUBJECT_ID, Long.MAX_VALUE, false);
        accountInterventionApiStub.initWithAccountStatus(
                SUBJECT_ID.getValue(), false, true, true, true);

        var session = redis.getSession(SESSION_ID);
        assertNotNull(session);
        var orchSession = orchSessionExtension.getSession(SESSION_ID);
        assertTrue(orchSession.isPresent());

        var response =
                makeRequest(
                        Optional.of(TEST_EMAIL_ADDRESS),
                        constructHeaders(
                                Optional.of(buildSessionCookie(SESSION_ID, CLIENT_SESSION_ID))),
                        constructQueryStringParameters());

        assertUserInfoStoredAndRedirectedToRp(response);
        assertOrchSessionIsUpdatedWithUserInfoClaims();

        assertOrchAuthCodeSaved(orchAuthCodeExtension, response);
    }

    @Test
    void byDefaultDoesNotThrowWhenAisReturns500() throws Json.JsonException {
        accountInterventionSetup();
        setupTestWithDefaultEnvVars();
        accountInterventionApiStub.initWithErrorResponse(SUBJECT_ID.getValue());

        var session = redis.getSession(SESSION_ID);
        assertNotNull(session);
        var orchSession = orchSessionExtension.getSession(SESSION_ID);
        assertTrue(orchSession.isPresent());

        assertDoesNotThrow(
                () ->
                        makeRequest(
                                Optional.of(TEST_EMAIL_ADDRESS),
                                constructHeaders(
                                        Optional.of(
                                                buildSessionCookie(SESSION_ID, CLIENT_SESSION_ID))),
                                constructQueryStringParameters()));
    }

    @Test
    void doesThrowWhenAisReturns500AndAbortFlagIsOn() throws Json.JsonException {
        accountInterventionSetup();
        setupTestWithAbortOnAisErrorResponseFlagOn();
        accountInterventionApiStub.initWithErrorResponse(SUBJECT_ID.getValue());

        var session = redis.getSession(SESSION_ID);
        assertNotNull(session);
        var orchSession = orchSessionExtension.getSession(SESSION_ID);
        assertTrue(orchSession.isPresent());

        assertThrows(
                AccountInterventionException.class,
                () ->
                        makeRequest(
                                Optional.of(TEST_EMAIL_ADDRESS),
                                constructHeaders(
                                        Optional.of(
                                                buildSessionCookie(SESSION_ID, CLIENT_SESSION_ID))),
                                constructQueryStringParameters()));
    }

    @Test
    void shouldRedirectToRpWhenFieldsAreMissingInResponse()
            throws Json.JsonException, ParseException {
        accountInterventionSetup();
        setupTestWithDefaultEnvVars();
        accountInterventionApiStub.initWithoutOptionalFields(
                SUBJECT_ID.getValue(), false, false, false, false);

        var session = redis.getSession(SESSION_ID);
        assertNotNull(session);
        var orchSession = orchSessionExtension.getSession(SESSION_ID);
        assertTrue(orchSession.isPresent());

        var response =
                makeRequest(
                        Optional.of(TEST_EMAIL_ADDRESS),
                        constructHeaders(
                                Optional.of(buildSessionCookie(SESSION_ID, CLIENT_SESSION_ID))),
                        constructQueryStringParameters());

        assertUserInfoStoredAndRedirectedToRp(response);
        assertOrchSessionIsUpdatedWithUserInfoClaims();

        assertOrchAuthCodeSaved(orchAuthCodeExtension, response);
    }

    void accountInterventionSetupWithIdentity() throws Json.JsonException {
        setupSession();
        setupClientRegWithIdentityVerificationSupported();
    }

    @Test
    void shouldRedirectToIpvWhenAccountStatusIsNoIntervention()
            throws Json.JsonException, java.text.ParseException, ParseException, JOSEException {
        accountInterventionSetupWithIdentity();
        setupTestWithDefaultEnvVars();
        accountInterventionApiStub.initWithAccountStatus(
                SUBJECT_ID.getValue(), false, false, false, false);

        var session = redis.getSession(SESSION_ID);
        assertNotNull(session);
        var orchSession = orchSessionExtension.getSession(SESSION_ID);
        assertTrue(orchSession.isPresent());

        var response =
                makeRequest(
                        Optional.of(TEST_EMAIL_ADDRESS),
                        constructHeaders(
                                Optional.of(buildSessionCookie(SESSION_ID, CLIENT_SESSION_ID))),
                        constructQueryStringParameters());

        assertRedirectToIpv(response, false);
        assertOrchSessionIsUpdatedWithUserInfoClaims();
    }

    @Test
    void shouldLogoutAndRedirectToBlockedPageWhenAccountStatusWithIdentityIsBlocked()
            throws Json.JsonException {
        setupTestWithDefaultEnvVars();
        accountInterventionSetupWithIdentity();
        accountInterventionApiStub.initWithAccountStatus(
                SUBJECT_ID.getValue(), true, false, false, false);

        var session = redis.getSession(SESSION_ID);
        assertNotNull(session);
        var orchSession = orchSessionExtension.getSession(SESSION_ID);
        assertTrue(orchSession.isPresent());

        var response =
                makeRequest(
                        Optional.of(TEST_EMAIL_ADDRESS),
                        constructHeaders(
                                Optional.of(buildSessionCookie(SESSION_ID, CLIENT_SESSION_ID))),
                        constructQueryStringParameters());

        assertRedirectToBlockedPage(response);
        assertSessionIsDeleted();
    }

    @Test
    void shouldRedirectToIpvpWhenAccountStatusIsSuspendedNoAction()
            throws Json.JsonException, java.text.ParseException, ParseException, JOSEException {
        accountInterventionSetupWithIdentity();
        setupTestWithDefaultEnvVars();
        accountInterventionApiStub.initWithAccountStatus(
                SUBJECT_ID.getValue(), false, false, false, false);

        var session = redis.getSession(SESSION_ID);
        assertNotNull(session);
        var orchSession = orchSessionExtension.getSession(SESSION_ID);
        assertTrue(orchSession.isPresent());

        var response =
                makeRequest(
                        Optional.of(TEST_EMAIL_ADDRESS),
                        constructHeaders(
                                Optional.of(buildSessionCookie(SESSION_ID, CLIENT_SESSION_ID))),
                        constructQueryStringParameters());

        assertRedirectToIpv(response, false);
        assertOrchSessionIsUpdatedWithUserInfoClaims();
    }

    @Test
    void
            shouldLogoutAndRedirectToSuspendedPageWhenAccountWithIdentityStatusIsSuspendedResetPassword()
                    throws Json.JsonException {
        accountInterventionSetupWithIdentity();
        setupTestWithDefaultEnvVars();
        accountInterventionApiStub.initWithAccountStatus(
                SUBJECT_ID.getValue(), false, true, false, true);

        var session = redis.getSession(SESSION_ID);
        assertNotNull(session);
        var orchSession = orchSessionExtension.getSession(SESSION_ID);
        assertTrue(orchSession.isPresent());

        var response =
                makeRequest(
                        Optional.of(TEST_EMAIL_ADDRESS),
                        constructHeaders(
                                Optional.of(buildSessionCookie(SESSION_ID, CLIENT_SESSION_ID))),
                        constructQueryStringParameters());

        assertRedirectToSuspendedPage(response);
        assertSessionIsDeleted();
    }

    @Test
    void shouldRedirectToIpvWhenAccountStatusIsSuspendedReproveIdentity()
            throws Json.JsonException, java.text.ParseException, ParseException, JOSEException {
        accountInterventionSetupWithIdentity();
        setupTestWithDefaultEnvVars();
        accountInterventionApiStub.initWithAccountStatus(
                SUBJECT_ID.getValue(), false, true, true, false);

        var session = redis.getSession(SESSION_ID);
        assertNotNull(session);
        var orchSession = orchSessionExtension.getSession(SESSION_ID);
        assertTrue(orchSession.isPresent());

        var response =
                makeRequest(
                        Optional.of(TEST_EMAIL_ADDRESS),
                        constructHeaders(
                                Optional.of(buildSessionCookie(SESSION_ID, CLIENT_SESSION_ID))),
                        constructQueryStringParameters());

        assertRedirectToIpv(response, true);
        assertOrchSessionIsUpdatedWithUserInfoClaims();
    }

    @Test
    void
            shouldRedirectToIpvWhenAccountStatusIsSuspendedResetPasswordAndPasswordWasResetAfterInterventionWasApplied()
                    throws Json.JsonException,
                            java.text.ParseException,
                            ParseException,
                            JOSEException {
        accountInterventionSetupWithIdentity();
        setupTestWithDefaultEnvVars();
        authExternalApiStub.init(SUBJECT_ID, Long.MAX_VALUE, false);
        accountInterventionApiStub.initWithAccountStatus(
                SUBJECT_ID.getValue(), false, true, false, true);

        var session = redis.getSession(SESSION_ID);
        assertNotNull(session);
        var orchSession = orchSessionExtension.getSession(SESSION_ID);
        assertTrue(orchSession.isPresent());

        var response =
                makeRequest(
                        Optional.of(TEST_EMAIL_ADDRESS),
                        constructHeaders(
                                Optional.of(buildSessionCookie(SESSION_ID, CLIENT_SESSION_ID))),
                        constructQueryStringParameters());

        assertRedirectToIpv(response, false);
        assertOrchSessionIsUpdatedWithUserInfoClaims();
    }

    @Test
    void
            shouldRedirectToIpvWhenAccountStatusIsSuspendedResetPasswordReproveIdentityAndPasswordWasResetAfterInterventionWasApplied()
                    throws Json.JsonException,
                            java.text.ParseException,
                            ParseException,
                            JOSEException {
        accountInterventionSetupWithIdentity();
        setupTestWithDefaultEnvVars();
        authExternalApiStub.init(SUBJECT_ID, Long.MAX_VALUE, false);
        accountInterventionApiStub.initWithAccountStatus(
                SUBJECT_ID.getValue(), false, true, true, true);

        var session = redis.getSession(SESSION_ID);
        assertNotNull(session);
        var orchSession = orchSessionExtension.getSession(SESSION_ID);
        assertTrue(orchSession.isPresent());

        var response =
                makeRequest(
                        Optional.of(TEST_EMAIL_ADDRESS),
                        constructHeaders(
                                Optional.of(buildSessionCookie(SESSION_ID, CLIENT_SESSION_ID))),
                        constructQueryStringParameters());

        assertRedirectToIpv(response, true);
        assertOrchSessionIsUpdatedWithUserInfoClaims();
    }

    @Test
    void doesThrowWhenAisReturns500AndAbortFlagIsOnWithIdentity() throws Json.JsonException {
        accountInterventionSetupWithIdentity();
        setupTestWithAbortOnAisErrorResponseFlagOn();
        accountInterventionApiStub.initWithErrorResponse(SUBJECT_ID.getValue());

        var session = redis.getSession(SESSION_ID);
        assertNotNull(session);
        var orchSession = orchSessionExtension.getSession(SESSION_ID);
        assertTrue(orchSession.isPresent());

        assertThrows(
                AccountInterventionException.class,
                () ->
                        makeRequest(
                                Optional.of(TEST_EMAIL_ADDRESS),
                                constructHeaders(
                                        Optional.of(
                                                buildSessionCookie(SESSION_ID, CLIENT_SESSION_ID))),
                                constructQueryStringParameters()));
    }

    @Test
    void shouldSetAuthTimeWhenUserHasBeenUplifted() {
        authExternalApiStub.init(SUBJECT_ID, Long.MAX_VALUE, true);
        assertAuthTimeHasNotBeenSetInOrchSessionTable();
        var orchSession = orchSessionExtension.getSession(SESSION_ID);
        orchSessionExtension.updateSession(orchSession.get().withAuthenticated(true));

        makeRequest(
                Optional.empty(),
                constructHeaders(Optional.of(buildSessionCookie(SESSION_ID, CLIENT_SESSION_ID))),
                constructQueryStringParameters());

        assertAuthTimeHasBeenSetInOrchSessionTable();
    }

    @Test
    void shouldSetAuthTimeWhenUserIsNotYetAuthenticated() {
        authExternalApiStub.init(SUBJECT_ID, Long.MAX_VALUE, false);
        assertAuthTimeHasNotBeenSetInOrchSessionTable();
        var orchSession = orchSessionExtension.getSession(SESSION_ID);
        orchSessionExtension.updateSession(orchSession.get().withAuthenticated(false));

        makeRequest(
                Optional.empty(),
                constructHeaders(Optional.of(buildSessionCookie(SESSION_ID, CLIENT_SESSION_ID))),
                constructQueryStringParameters());

        assertAuthTimeHasBeenSetInOrchSessionTable();
    }

    @Nested
    class MaxAgeSessionHandling {
        private static final String PREVIOUS_SESSION_ID = "9a3f2708-2bf1-40d8-9c25-7b94145ef535";
        private static final String INTERNAL_COMMON_SUBJECT_ID = SUBJECT_ID.getValue();
        private static final String DIFFERENT_INTERNAL_COMMON_SUBJECT_ID =
                "urn:fdc:gov:cebb94a1-3ee7-44ed-963b-f3befee65487";
        private static final List<String> PREVIOUS_CLIENT_SESSIONS =
                List.of(
                        "623f860d-1bce-43ea-8f82-446fc894160b",
                        "3eee3869-abf1-41c1-bdb5-c25f68d0a54d",
                        "aef54391-95d8-4d3b-ac30-cbe1e3e2f0d4");

        private static final List<String> PREVIOUS_CLIENTS_FOR_CLIENT_SESSION =
                List.of("client-id-1", "client-id-2", "client-id-3");

        private static final List<String> PREVIOUS_RP_PAIRWISE_IDS_FOR_CLIENT_SESSION =
                List.of(
                        "rp-pairwise-id-client-1",
                        "rp-pairwise-id-client-2",
                        "rp-pairwise-id-client-3");

        @Test
        void updatesOrchSessionWhenPreviousCommonSubjectIdMatchesAuthUserInfoResponse()
                throws Json.JsonException, ParseException {
            authExternalApiStub.init(
                    new Subject(INTERNAL_COMMON_SUBJECT_ID), Long.MAX_VALUE, false);
            setupMaxAgeSession();
            setupPreviousSessions(INTERNAL_COMMON_SUBJECT_ID);

            var response =
                    makeRequest(
                            Optional.empty(),
                            constructHeaders(
                                    Optional.of(buildSessionCookie(SESSION_ID, CLIENT_SESSION_ID))),
                            constructQueryStringParameters());

            assertUserInfoStoredAndRedirectedToRp(response);

            var orchSession = orchSessionExtension.getSession(SESSION_ID).get();
            var expectedClientSessions = new ArrayList<>(List.of(CLIENT_SESSION_ID));
            expectedClientSessions.addAll(PREVIOUS_CLIENT_SESSIONS);
            assertEquals(expectedClientSessions.stream().toList(), orchSession.getClientSessions());
            assertNull(orchSession.getPreviousSessionId());
        }

        @Test
        void doesNotUpdateOrchSessionWhenPreviousCommonSubjectIdDoesNotMatchUserInfoResponse()
                throws Json.JsonException {
            authExternalApiStub.init(
                    new Subject(INTERNAL_COMMON_SUBJECT_ID), Long.MAX_VALUE, false);
            setupMaxAgeSession();
            setupPreviousSessions(DIFFERENT_INTERNAL_COMMON_SUBJECT_ID);
            setupPreviousClientsAndPreviousClientSessions();
            // Sending back channel logouts requires a user store entry
            userStore.signUp(TEST_EMAIL_ADDRESS, "");

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
                            AccountInterventionsAuditableEvent.AIS_RESPONSE_RECEIVED,
                            OidcAuditableEvent.AUTHENTICATION_COMPLETE,
                            LogoutAuditableEvent.LOG_OUT_SUCCESS,
                            OidcAuditableEvent.AUTH_CODE_ISSUED));

            var orchSession = orchSessionExtension.getSession(SESSION_ID).get();
            assertEquals(List.of(CLIENT_SESSION_ID), orchSession.getClientSessions());
            assertNull(orchSession.getPreviousSessionId());
            assertBackChannelLogoutsSent(PREVIOUS_CLIENTS_FOR_CLIENT_SESSION);
        }

        private void setupMaxAgeSession() throws Json.JsonException {
            var session = new Session();
            redis.addSessionWithId(session, SESSION_ID);
            redis.addStateToRedis(
                    AuthenticationAuthorizationService.AUTHENTICATION_STATE_STORAGE_PREFIX,
                    ORCH_TO_AUTH_STATE,
                    SESSION_ID);
            setUpClientSession();
            orchSessionExtension.addSession(
                    new OrchSessionItem(SESSION_ID)
                            .withPreviousSessionId(PREVIOUS_SESSION_ID)
                            .addClientSession(CLIENT_SESSION_ID));
        }

        private void setupPreviousSessions(String internalCommonSubjectId)
                throws Json.JsonException {
            var session = new Session().setEmailAddress(TEST_EMAIL_ADDRESS);
            var orchSession =
                    new OrchSessionItem(PREVIOUS_SESSION_ID)
                            .withInternalCommonSubjectId(internalCommonSubjectId)
                            .withAuthTime(
                                    NowHelper.nowMinus(1, ChronoUnit.HOURS)
                                            .toInstant()
                                            .getEpochSecond());
            PREVIOUS_CLIENT_SESSIONS.forEach(orchSession::addClientSession);
            redis.addSessionWithId(session, PREVIOUS_SESSION_ID);
            redis.addStateToRedis(
                    AuthenticationAuthorizationService.AUTHENTICATION_STATE_STORAGE_PREFIX,
                    ORCH_TO_AUTH_STATE,
                    SESSION_ID);
            setUpClientSession();
            orchSessionExtension.addSession(orchSession);
        }

        private void setupPreviousClientsAndPreviousClientSessions() throws Json.JsonException {
            PREVIOUS_CLIENTS_FOR_CLIENT_SESSION.forEach(
                    AuthenticationCallbackHandlerIntegrationTest.this::setupClientRegWithClientId);
            for (String clientSessionId : PREVIOUS_CLIENT_SESSIONS) {
                var index = PREVIOUS_CLIENT_SESSIONS.indexOf(clientSessionId);
                setupClientSessionWithId(
                        clientSessionId,
                        PREVIOUS_CLIENTS_FOR_CLIENT_SESSION.get(index),
                        PREVIOUS_RP_PAIRWISE_IDS_FOR_CLIENT_SESSION.get(index));
            }
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
                containsString(
                        buildURI(configurationService.getAuthFrontendBaseURL(), SUSPENDED_ENDPOINT)
                                .toString()));

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
                containsString(
                        buildURI(configurationService.getAuthFrontendBaseURL(), BLOCKED_ENDPOINT)
                                .toString()));

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
        var signedJWTResponse = validateAndDecryptRequestObject(response);

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

    private SignedJWT validateAndDecryptRequestObject(APIGatewayProxyResponseEvent response)
            throws ParseException, JOSEException {
        var authRequest = validateQueryRequestToIPVAndReturnAuthRequest(response);

        var encryptedRequestObject = authRequest.getRequestObject();
        return decryptJWT((EncryptedJWT) encryptedRequestObject);
    }

    private void assertInformationStoredForNoSessionService(APIGatewayProxyResponseEvent response)
            throws java.text.ParseException, ParseException, JOSEException {
        var requestObject = validateAndDecryptRequestObject(response);
        var state = requestObject.getJWTClaimsSet().getClaim("state");
        var noSessionObject = redis.getFromRedis("state:" + state);
        assertEquals(CLIENT_SESSION_ID, noSessionObject);
    }

    private void assertUserInfoStoredAndRedirectedToRp(APIGatewayProxyResponseEvent response)
            throws ParseException {
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

        Optional<UserInfo> userInfo =
                userInfoStoreExtension.getAuthenticationUserInfo(
                        SUBJECT_ID.getValue(), CLIENT_SESSION_ID);
        assertTrue(userInfo.isPresent());
        assertEquals(SUBJECT_ID, userInfo.get().getSubject());
        assertEquals(true, userInfo.get().getBooleanClaim("new_account"));
    }

    private void assertOrchSessionIsUpdatedWithUserInfoClaims() {
        Optional<OrchSessionItem> orchSession = orchSessionExtension.getSession(SESSION_ID);
        assertTrue(orchSession.isPresent());
        assertEquals(
                MFAMethodType.AUTH_APP.getValue(), orchSession.get().getVerifiedMfaMethodType());
        assertThat(OrchSessionItem.AccountState.NEW, equalTo(orchSession.get().getIsNewAccount()));
    }

    private void assertAuthTimeHasBeenSetInOrchSessionTable() {
        Optional<OrchSessionItem> orchSession = orchSessionExtension.getSession(SESSION_ID);
        assertTrue(orchSession.isPresent());
        assertNotEquals(null, orchSession.get().getAuthTime());
    }

    private void assertAuthTimeHasNotBeenSetInOrchSessionTable() {
        Optional<OrchSessionItem> orchSession = orchSessionExtension.getSession(SESSION_ID);
        assertTrue(orchSession.isPresent());
        assertEquals(null, orchSession.get().getAuthTime());
    }

    private void assertSessionIsDeleted() {
        var session = redis.getFromRedis(SESSION_ID);
        var orchSession = orchSessionExtension.getSession(SESSION_ID);
        assertNull(session);
        assertTrue(orchSession.isEmpty());
    }

    private void setupClientRegWithClientId(String clientId) {
        clientStore.registerClient(
                clientId,
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
                false);
    }

    private void setupClientReg(boolean identityVerificationSupported) {
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
                identityVerificationSupported);
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
        handler = new AuthenticationCallbackHandler(configurationService, redisConnectionService);
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
        orchSessionExtension.addSession(new OrchSessionItem(SESSION_ID));
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
        public String getAccountInterventionsErrorMetricName() {
            return "AISException";
        }

        @Override
        public boolean abortOnAccountInterventionsErrorResponse() {
            return this.abortOnAisErrorResponse;
        }

        @Override
        public String getBackChannelLogoutQueueURI() {
            return backChannelLogoutQueueExtension.getQueueUrl();
        }
    }

    public void setupClientSessionWithId(
            String clientSessionId, String clientId, String rpPairwiseId)
            throws Json.JsonException {
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
                                ResponseType.CODE, SCOPE, new ClientID(clientId), REDIRECT_URI)
                        .state(RP_STATE)
                        .nonce(new Nonce())
                        .customParameter("vtr", jsonArrayOf(vtrStr1, vtrStr2));
        var creationDate = LocalDateTime.now();
        var clientSession =
                new ClientSession(
                                authRequestBuilder.build().toParameters(),
                                creationDate,
                                vtrList,
                                CLIENT_NAME)
                        .setRpPairwiseId(rpPairwiseId);

        redis.createClientSession(clientSessionId, clientSession);
        orchClientSessionExtension.storeClientSession(
                new OrchClientSessionItem(
                                clientSessionId,
                                authRequestBuilder.build().toParameters(),
                                creationDate,
                                vtrList,
                                CLIENT_NAME)
                        .withRpPairwiseId(rpPairwiseId));
    }

    private void setUpClientSession() throws Json.JsonException {
        setupClientSessionWithId(CLIENT_SESSION_ID, CLIENT_ID, null);
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

    private void assertBackChannelLogoutsSent(List<String> clientIds) {
        await().atMost(Duration.of(1, ChronoUnit.SECONDS))
                .untilAsserted(
                        () ->
                                assertThat(
                                        backChannelLogoutQueueExtension
                                                .getApproximateMessageCount(),
                                        equalTo(clientIds.size())));

        var events = backChannelLogoutQueueExtension.getMessages(BackChannelLogoutMessage.class);
        assertTrue(
                clientIds.stream()
                        .allMatch(
                                clientId ->
                                        events.stream()
                                                .anyMatch(
                                                        backChannelLogoutMessage ->
                                                                backChannelLogoutMessage
                                                                        .getClientId()
                                                                        .equals(clientId))));
    }
}

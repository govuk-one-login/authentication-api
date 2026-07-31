package uk.gov.di.orchestration.sis.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseMode;
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
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import net.minidev.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.ipv.services.InitiateIPVAuthorisationService;
import uk.gov.di.orchestration.audit.AuditContext;
import uk.gov.di.orchestration.audit.TxmaAuditUser;
import uk.gov.di.orchestration.identity.entity.CrossBrowserNoSessionException;
import uk.gov.di.orchestration.identity.entity.CrossBrowserStateMismatchException;
import uk.gov.di.orchestration.identity.entity.IdentityContext;
import uk.gov.di.orchestration.identity.helpers.IdentityCallbackHelper;
import uk.gov.di.orchestration.identity.service.IdentityContextService;
import uk.gov.di.orchestration.shared.domain.AuditableEvent;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.CredentialTrustLevel;
import uk.gov.di.orchestration.shared.entity.CrossBrowserEntity;
import uk.gov.di.orchestration.shared.entity.LevelOfConfidence;
import uk.gov.di.orchestration.shared.entity.OrchClientSessionItem;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem;
import uk.gov.di.orchestration.shared.entity.ResponseHeaders;
import uk.gov.di.orchestration.shared.entity.VectorOfTrust;
import uk.gov.di.orchestration.shared.exceptions.NoSessionException;
import uk.gov.di.orchestration.shared.helpers.IdGenerator;
import uk.gov.di.orchestration.shared.oauth.OAuthService;
import uk.gov.di.orchestration.shared.services.AuditService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.EndOfJourneyService;
import uk.gov.di.orchestration.shared.services.RedirectService;
import uk.gov.di.orchestration.sis.exception.SISCallbackValidationError;

import java.net.URI;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.orchestration.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.orchestration.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;
import static uk.gov.di.orchestration.sis.domain.SISAuditableEvent.ORCH_SIS_UNSUCCESSFUL_AUTHORISATION_RESPONSE_RECEIVED;

public class SISCallbackHandlerTest {
    private final Context context = mock(Context.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final IdentityCallbackHelper identityCallbackHelper =
            mock(IdentityCallbackHelper.class);
    private final IdentityContextService identityContextService =
            mock(IdentityContextService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final EndOfJourneyService endOfJourneyService = mock(EndOfJourneyService.class);
    private final OAuthService sisAuthorisationService = mock(OAuthService.class);
    private final InitiateIPVAuthorisationService ipvAuthorisationService =
            mock(InitiateIPVAuthorisationService.class);

    private static final URI FRONT_END_ERROR_URI = URI.create("https://example.com/error");
    private static final URI FRONT_END_SESSION_ENDED_URI =
            URI.create("https://example.com/session-ended");
    private static final String FRONT_END_AIS_LOGOUT_URL = "https://example.com/ais-logout";
    private static final AuthorizationCode AUTH_CODE = new AuthorizationCode();
    private static final String COOKIE = "Cookie";
    private static final String SESSION_ID = "a-session-id";
    private static final String CLIENT_SESSION_ID = "a-client-session-id";
    private static final List<String> REQUESTED_LOCS = List.of("P2", "P0");
    private static final String PERSISTENT_SESSION_ID = IdGenerator.generate() + "--1700558480962";
    private static final State STATE = new State();
    private static final URI REDIRECT_URI = URI.create("http://rp-redirect");
    private static final State RP_STATE = new State();
    private static final ClientID CLIENT_ID = new ClientID("test-client-id");
    private static final AuthenticationRequest NO_SESSION_AUTH_REQUEST = generateAuthRequest(null);
    private static final String TEST_INTERNAL_COMMON_SUBJECT_IDENTIFIER =
            "urn:fdc:gov.uk:2022:0VzHWj9aaJpyHXJX8B5QJ-UOUibweHmkSg1GjF6w9yM";
    private static final UserInfo AUTH_USER_INFO = generateAuthUserInfo();
    private static final SISCallbackValidationError GENERIC_ACCESS_DENIED_ERROR =
            new SISCallbackValidationError("access_denied", "No access", true, false);
    private static final SISCallbackValidationError UPDATE_REQUESTED_ERROR =
            new SISCallbackValidationError("access_denied", "record_update_requested", true, true);
    private static final SISCallbackValidationError GENERIC_ERROR =
            new SISCallbackValidationError("generic_error", "uh oh", false, false);

    private static final URI IPV_URI = URI.create("http://ipv-uri");
    private static final CrossBrowserEntity NO_SESSION_ENTITY =
            new CrossBrowserEntity(
                    "test-csid",
                    new ErrorObject("test-error", "Test Description"),
                    new OrchClientSessionItem("test-csid")
                            .withAuthRequestParams(NO_SESSION_AUTH_REQUEST.toParameters()));
    private static final AuthenticationRequest MISMATCH_STATE_AUTH_REQUEST =
            generateAuthRequest(null);
    private static final CrossBrowserEntity MISMATCH_STATE_ENTITY =
            new CrossBrowserEntity(
                    "test-csid-2",
                    new ErrorObject("state-mismatch", "Test Description"),
                    new OrchClientSessionItem("test-csid-2")
                            .withAuthRequestParams(MISMATCH_STATE_AUTH_REQUEST.toParameters()));
    private static final URI ACCESS_DENIED_URI =
            new AuthenticationErrorResponse(
                            URI.create(REDIRECT_URI.toString()),
                            OAuth2Error.ACCESS_DENIED,
                            RP_STATE,
                            null)
                    .toURI();

    private final OrchSessionItem orchSession =
            new OrchSessionItem(SESSION_ID)
                    .withInternalCommonSubjectId(TEST_INTERNAL_COMMON_SUBJECT_IDENTIFIER);
    private final AuthenticationRequest authRequest = generateAuthRequest(new OIDCClaimsRequest());
    private final OrchClientSessionItem orchClientSession =
            new OrchClientSessionItem(
                            CLIENT_SESSION_ID,
                            authRequest.toParameters(),
                            null,
                            List.of(
                                    VectorOfTrust.of(
                                            CredentialTrustLevel.MEDIUM_LEVEL,
                                            LevelOfConfidence.MEDIUM_LEVEL),
                                    VectorOfTrust.of(
                                            CredentialTrustLevel.MEDIUM_LEVEL,
                                            LevelOfConfidence.NONE)),
                            "test-client-name")
                    .withRpPairwiseId(
                            "urn:fdc:gov.uk:2022:_WJvfEzqmWo6vnDwSqgMPTC-aK8n_fkgZsNF-a4OxxU");
    private final ClientRegistry client = generateClientRegistryNoClaims();
    private SISCallbackHandler handler;

    @BeforeEach
    void setup() {
        when(identityCallbackHelper.redirectToFrontendErrorPageWithErrorLog(any(Throwable.class)))
                .thenReturn(
                        RedirectService.redirectToFrontendErrorPageWithErrorLog(
                                FRONT_END_ERROR_URI, new Error("error")));
        when(identityCallbackHelper.redirectToFrontendErrorPageForNoSession(any(Exception.class)))
                .thenReturn(
                        RedirectService.redirectToFrontendErrorPageWithErrorLog(
                                FRONT_END_SESSION_ENDED_URI, new Error("error")));
        when(endOfJourneyService.generateAuthenticationErrorResponse(
                        eqAuthRequest(NO_SESSION_AUTH_REQUEST),
                        eq(NO_SESSION_ENTITY.getErrorObject()),
                        eq("No Session Error: true")))
                .thenReturn(
                        generateApiGatewayProxyResponse(
                                302,
                                "",
                                Map.of(ResponseHeaders.LOCATION, REDIRECT_URI.toString()),
                                null));
        when(endOfJourneyService.generateAuthenticationErrorResponse(any(), any()))
                .thenReturn(
                        generateApiGatewayProxyResponse(
                                302,
                                "",
                                Map.of(ResponseHeaders.LOCATION, ACCESS_DENIED_URI.toString()),
                                null));
        when(endOfJourneyService.generateAuthenticationErrorResponse(
                        eqAuthRequest(MISMATCH_STATE_AUTH_REQUEST),
                        eq(MISMATCH_STATE_ENTITY.getErrorObject()),
                        eq("No Session Error: false")))
                .thenReturn(
                        generateApiGatewayProxyResponse(
                                302,
                                "",
                                Map.of(ResponseHeaders.LOCATION, REDIRECT_URI.toString()),
                                null));

        when(configurationService.isIdentityEnabled()).thenReturn(true);
        handler =
                new SISCallbackHandler(
                        configurationService,
                        identityCallbackHelper,
                        identityContextService,
                        auditService,
                        endOfJourneyService,
                        sisAuthorisationService,
                        ipvAuthorisationService);
    }

    @Test
    void shouldRedirectToErrorPageWhenIdentityIsDisabled() {
        when(configurationService.isIdentityEnabled()).thenReturn(false);
        var request = createRequestEvent();

        var response = handler.handleRequest(request, context);

        assertDoesRedirectToPage(response, FRONT_END_ERROR_URI.toString());
        verifyNoInteractions(auditService);
    }

    @Test
    void shouldRedirectToErrorPageWhenNoSessionCookiesAreSetAndSessionFoundUsingState()
            throws Exception {
        var request = createRequestEvent();
        when(identityContextService.buildContext(request))
                .thenThrow(new CrossBrowserNoSessionException(NO_SESSION_ENTITY));

        var response = handler.handleRequest(request, context);

        assertDoesRedirectToPage(response, REDIRECT_URI.toString());
        assertAuditEventSubmitted(ORCH_SIS_UNSUCCESSFUL_AUTHORISATION_RESPONSE_RECEIVED);
        verifyNoMoreInteractions(auditService);
    }

    @Test
    void shouldRedirectToErrorPageWhenNoSessionFoundInContextService() throws Exception {
        var request = createRequestEvent();
        when(identityContextService.buildContext(request))
                .thenThrow(new NoSessionException("Session not found"));

        var response = handler.handleRequest(request, context);

        assertDoesRedirectToPage(response, FRONT_END_SESSION_ENDED_URI.toString());
        verifyNoInteractions(auditService);
    }

    @Test
    void shouldRedirectToErrorPageWhenStateInParamsDoesNotMatchStateFromClientSession()
            throws Exception {
        var request = createRequestEvent();
        when(identityContextService.buildContext(request))
                .thenThrow(new CrossBrowserStateMismatchException(MISMATCH_STATE_ENTITY));

        var response = handler.handleRequest(request, context);

        assertDoesRedirectToPage(response, REDIRECT_URI.toString());
        assertAuditEventSubmitted(ORCH_SIS_UNSUCCESSFUL_AUTHORISATION_RESPONSE_RECEIVED);
        verifyNoMoreInteractions(auditService);
    }

    @Test
    void shouldRedirectToErrorPageWhenAuthRequestParamsInvalid() throws Exception {
        var request = createRequestEvent();
        when(identityContextService.buildContext(request))
                .thenThrow(new ParseException("Auth request failed to parse"));

        var response = handler.handleRequest(request, context);
        assertDoesRedirectToPage(response, FRONT_END_ERROR_URI.toString());
        verifyNoInteractions(auditService);
    }

    @Nested
    class SISResponseValidation {
        @Test
        void shouldRedirectToIPVWhenSISReturnsAccessDeniedError() throws Exception {
            var request =
                    createRequestEvent(
                            Map.of("error", "access_denied", "error_description", "No access"));
            usingValidIdentityContext(request);
            mockIpvRedirect(request, false);
            when(sisAuthorisationService.validateCallback(
                            request.getQueryStringParameters(), SESSION_ID))
                    .thenReturn(Optional.of(GENERIC_ACCESS_DENIED_ERROR));

            var response = handler.handleRequest(request, context);

            assertDoesRedirectToPage(response, IPV_URI.toString());
            assertAuditEventSubmitted(ORCH_SIS_UNSUCCESSFUL_AUTHORISATION_RESPONSE_RECEIVED);
            verifyNoMoreInteractions(auditService);
        }

        @Test
        void
                shouldRedirectToIPVWithUpdateIdentityClaimWhenSISReturnsAccessDeniedErrorWithUpdateIdentityDescription()
                        throws Exception {
            var request =
                    createRequestEvent(
                            Map.of(
                                    "error",
                                    "access_denied",
                                    "error_description",
                                    "record_update_requested"));
            usingValidIdentityContext(request);
            mockIpvRedirect(request, true);
            when(sisAuthorisationService.validateCallback(
                            request.getQueryStringParameters(), SESSION_ID))
                    .thenReturn(Optional.of(UPDATE_REQUESTED_ERROR));

            var response = handler.handleRequest(request, context);

            assertDoesRedirectToPage(response, IPV_URI.toString());
            assertAuditEventSubmitted(ORCH_SIS_UNSUCCESSFUL_AUTHORISATION_RESPONSE_RECEIVED);
            verifyNoMoreInteractions(auditService);
        }

        @Test
        void shouldRedirectToLogoutPageWhenAISInterventionOccursAfterSISErrorCheck()
                throws Exception {
            var request =
                    createRequestEvent(
                            Map.of("error", "generic_error", "error_description", "uh oh"));
            usingValidIdentityContext(request);
            when(sisAuthorisationService.validateCallback(
                            request.getQueryStringParameters(), SESSION_ID))
                    .thenReturn(Optional.of(GENERIC_ERROR));
            mockAisIntervention();

            var response = handler.handleRequest(request, context);

            assertDoesRedirectToPage(response, FRONT_END_AIS_LOGOUT_URL);
            assertAuditEventSubmitted(ORCH_SIS_UNSUCCESSFUL_AUTHORISATION_RESPONSE_RECEIVED);
            verifyNoMoreInteractions(auditService);
        }

        @Test
        void shouldRedirectBackToRPWithErrorWhenSISReturnsGenericErrorThatIsNotAccessDenied()
                throws Exception {
            var request =
                    createRequestEvent(
                            Map.of("error", "generic_error", "error_description", "uh oh"));
            usingValidIdentityContext(request);
            when(sisAuthorisationService.validateCallback(
                            request.getQueryStringParameters(), SESSION_ID))
                    .thenReturn(Optional.of(GENERIC_ERROR));

            var response = handler.handleRequest(request, context);

            assertDoesRedirectToPage(
                    response,
                    REDIRECT_URI
                            + "?error=access_denied"
                            + "&error_description=Access+denied+by+resource+owner+or+authorization+server"
                            + "&state="
                            + authRequest.getState());
            assertAuditEventSubmitted(ORCH_SIS_UNSUCCESSFUL_AUTHORISATION_RESPONSE_RECEIVED);
            verifyNoMoreInteractions(auditService);
        }

        private void mockIpvRedirect(APIGatewayProxyRequestEvent request, boolean updateRequested) {
            when(ipvAuthorisationService.sendRequestToIPV(
                            eq(request),
                            eqAuthRequest(authRequest),
                            eq(AUTH_USER_INFO),
                            eq(SESSION_ID),
                            eq(client),
                            eq(CLIENT_ID.getValue()),
                            eq(CLIENT_SESSION_ID),
                            eq(PERSISTENT_SESSION_ID),
                            eq(false),
                            eq(REQUESTED_LOCS),
                            eq(updateRequested)))
                    .thenReturn(
                            generateApiGatewayProxyResponse(
                                    302,
                                    "",
                                    Map.of(ResponseHeaders.LOCATION, IPV_URI.toString()),
                                    null));
        }
    }

    private APIGatewayProxyRequestEvent createRequestEvent() {
        return createRequestEvent(Map.of());
    }

    private APIGatewayProxyRequestEvent createRequestEvent(Map<String, String> extraParams) {
        Map<String, String> responseParams = new HashMap<>();
        responseParams.put("code", AUTH_CODE.getValue());
        responseParams.put("state", STATE.getValue());
        responseParams.putAll(extraParams);
        var event = new APIGatewayProxyRequestEvent();
        event.setQueryStringParameters(responseParams);
        event.setHeaders(Map.of(COOKIE, buildCookieString()));
        return event;
    }

    public static AuthenticationRequest generateAuthRequest(OIDCClaimsRequest oidcClaimsRequest) {
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        Scope scope = new Scope();
        Nonce nonce = new Nonce();
        scope.add(OIDCScopeValue.OPENID);
        scope.add("phone");
        scope.add("email");
        return new AuthenticationRequest.Builder(responseType, scope, CLIENT_ID, REDIRECT_URI)
                .state(RP_STATE)
                .nonce(nonce)
                .claims(oidcClaimsRequest)
                .responseMode(ResponseMode.QUERY)
                .build();
    }

    private static ClientRegistry generateClientRegistryNoClaims() {
        return new ClientRegistry()
                .withClientID(CLIENT_ID.getValue())
                .withClientName("test-client")
                .withRedirectUrls(singletonList(REDIRECT_URI.toString()))
                .withSectorIdentifierUri("https://test.com")
                .withSubjectType("pairwise");
    }

    private static UserInfo generateAuthUserInfo() {
        return new UserInfo(
                new JSONObject(
                        Map.of(
                                "sub",
                                TEST_INTERNAL_COMMON_SUBJECT_IDENTIFIER,
                                "client_session_id",
                                CLIENT_SESSION_ID,
                                "email",
                                "test-email-address",
                                "phone_number",
                                "012345678902",
                                "salt",
                                "TW1jNDhpbUV1TzVra1ZXN050WFZ0eDVoMG1iQ1RmWHNxWGRXdmJSTXpkdz0=",
                                "local_account_id",
                                new Subject().getValue())));
    }

    private static String buildCookieString() {
        return format(
                "%s=%s.%s; Max-Age=%d; %s di-persistent-session-id=%s; Max-Age=34190000; Domain=auth.ida.digital.cabinet-office.gov.uk; Secure; HttpOnly;",
                "gs",
                SESSION_ID,
                CLIENT_SESSION_ID,
                3600,
                "Secure; HttpOnly;",
                PERSISTENT_SESSION_ID);
    }

    private void usingValidIdentityContext(APIGatewayProxyRequestEvent request) throws Exception {
        when(identityContextService.buildContext(request))
                .thenReturn(
                        new IdentityContext(
                                orchSession,
                                orchClientSession,
                                client,
                                AUTH_USER_INFO,
                                authRequest));
    }

    private void mockAisIntervention() {
        when(endOfJourneyService.getAndCheckForIntervention(
                        eq(orchSession),
                        any(AuditContext.class),
                        any(TxmaAuditUser.class),
                        eq(CLIENT_ID.getValue()),
                        eq(false)))
                .thenReturn(
                        Optional.of(
                                generateApiGatewayProxyResponse(
                                        302,
                                        null,
                                        Map.of("Location", FRONT_END_AIS_LOGOUT_URL),
                                        null)));
    }

    private void assertDoesRedirectToPage(APIGatewayProxyResponseEvent response, String page) {
        assertThat(response, hasStatus(302));
        assertEquals(page, response.getHeaders().get("Location"));
    }

    private void assertAuditEventSubmitted(AuditableEvent event) {
        verify(auditService)
                .submitAuditEvent(eq(event), eq(CLIENT_ID.getValue()), any(TxmaAuditUser.class));
    }

    private static AuthenticationRequest eqAuthRequest(AuthenticationRequest expectedAuthRequest) {
        return argThat(
                actualAuthRequest ->
                        actualAuthRequest != null
                                && expectedAuthRequest
                                        .toParameters()
                                        .equals(actualAuthRequest.toParameters()));
    }
}

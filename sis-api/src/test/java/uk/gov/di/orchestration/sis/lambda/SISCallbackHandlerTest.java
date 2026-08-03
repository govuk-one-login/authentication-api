package uk.gov.di.orchestration.sis.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.AccessTokenResponse;
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
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
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
import uk.gov.di.orchestration.identity.exceptions.IdentityCallbackException;
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
import uk.gov.di.orchestration.shared.exceptions.UnsuccessfulCredentialResponseException;
import uk.gov.di.orchestration.shared.helpers.IdGenerator;
import uk.gov.di.orchestration.shared.services.AuditService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.EndOfJourneyService;
import uk.gov.di.orchestration.shared.services.RedirectService;
import uk.gov.di.orchestration.sis.exception.SISCallbackValidationError;
import uk.gov.di.orchestration.sis.service.SISAuthorisationService;

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
import static uk.gov.di.orchestration.shared.entity.ValidClaims.RETURN_CODE;
import static uk.gov.di.orchestration.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.orchestration.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;
import static uk.gov.di.orchestration.sis.domain.SISAuditableEvent.AUTH_AUTH_CODE_ISSUED;
import static uk.gov.di.orchestration.sis.domain.SISAuditableEvent.ORCH_SIS_SUCCESSFUL_AUTHORISATION_RESPONSE_RECEIVED;
import static uk.gov.di.orchestration.sis.domain.SISAuditableEvent.ORCH_SIS_SUCCESSFUL_IDENTITY_RESPONSE_RECEIVED;
import static uk.gov.di.orchestration.sis.domain.SISAuditableEvent.ORCH_SIS_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED;
import static uk.gov.di.orchestration.sis.domain.SISAuditableEvent.ORCH_SIS_UNSUCCESSFUL_AUTHORISATION_RESPONSE_RECEIVED;
import static uk.gov.di.orchestration.sis.domain.SISAuditableEvent.ORCH_SIS_UNSUCCESSFUL_TOKEN_RESPONSE_RECEIVED;

public class SISCallbackHandlerTest {
    private final Context context = mock(Context.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final IdentityCallbackHelper identityCallbackHelper =
            mock(IdentityCallbackHelper.class);
    private final IdentityContextService identityContextService =
            mock(IdentityContextService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final EndOfJourneyService endOfJourneyService = mock(EndOfJourneyService.class);
    private final SISAuthorisationService sisAuthorisationService =
            mock(SISAuthorisationService.class);
    private final InitiateIPVAuthorisationService ipvAuthorisationService =
            mock(InitiateIPVAuthorisationService.class);

    private static final URI FRONT_END_ERROR_URI = URI.create("https://example.com/error");
    private static final URI FRONT_END_SESSION_ENDED_URI =
            URI.create("https://example.com/session-ended");
    private static final String FRONT_END_AIS_LOGOUT_URL = "https://example.com/ais-logout";
    private static final AuthorizationCode AUTH_CODE = new AuthorizationCode();
    private static final AuthorizationCode NEW_AUTH_CODE = new AuthorizationCode();
    private static final String COOKIE = "Cookie";
    private static final String SESSION_ID = "a-session-id";
    private static final String CLIENT_SESSION_ID = "a-client-session-id";
    private static final List<LevelOfConfidence> REQUESTED_LOCS =
            List.of(LevelOfConfidence.MEDIUM_LEVEL, LevelOfConfidence.NONE);
    private static final String PERSISTENT_SESSION_ID = IdGenerator.generate() + "--1700558480962";
    private static final State STATE = new State();
    private static final URI REDIRECT_URI = URI.create("http://rp-redirect");
    private static final State RP_STATE = new State();
    private static final ClientID CLIENT_ID = new ClientID("test-client-id");
    private static final AuthenticationRequest NO_SESSION_AUTH_REQUEST = generateAuthRequest(null);
    private static final String TEST_INTERNAL_COMMON_SUBJECT_IDENTIFIER =
            "urn:fdc:gov.uk:2022:0VzHWj9aaJpyHXJX8B5QJ-UOUibweHmkSg1GjF6w9yM";
    private static final String RP_PAIRWISE_SUBJECT =
            "urn:fdc:gov.uk:2022:_WJvfEzqmWo6vnDwSqgMPTC-aK8n_fkgZsNF-a4OxxU";
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
    private static final APIGatewayProxyResponseEvent GENERIC_ERROR_REDIRECT =
            RedirectService.redirectToFrontendErrorPageWithErrorLog(
                    FRONT_END_ERROR_URI, new Error("error"));
    private static final AccessTokenResponse SUCCESSFUL_TOKEN_RESPONSE =
            new AccessTokenResponse(new Tokens(new BearerAccessToken(), null));
    private static final URI SIS_BACKEND_URI = URI.create("http://sis-backend");

    private final OrchSessionItem orchSession =
            new OrchSessionItem(SESSION_ID)
                    .withInternalCommonSubjectId(TEST_INTERNAL_COMMON_SUBJECT_IDENTIFIER);
    private final AuthenticationRequest authRequestWithNoClaims =
            generateAuthRequest(new OIDCClaimsRequest());
    private final OrchClientSessionItem orchClientSession =
            new OrchClientSessionItem(
                            CLIENT_SESSION_ID,
                            authRequestWithNoClaims.toParameters(),
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
                .thenReturn(GENERIC_ERROR_REDIRECT);
        when(identityCallbackHelper.redirectToFrontendErrorPageWithWarnLog(any(Exception.class)))
                .thenReturn(GENERIC_ERROR_REDIRECT);
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
        when(configurationService.getSISBackendURI()).thenReturn(SIS_BACKEND_URI);
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
        assertAuditEventsSubmitted(ORCH_SIS_UNSUCCESSFUL_AUTHORISATION_RESPONSE_RECEIVED);
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
        assertAuditEventsSubmitted(ORCH_SIS_UNSUCCESSFUL_AUTHORISATION_RESPONSE_RECEIVED);
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
            when(sisAuthorisationService.validateResponse(
                            request.getQueryStringParameters(), SESSION_ID))
                    .thenReturn(Optional.of(GENERIC_ACCESS_DENIED_ERROR));

            var response = handler.handleRequest(request, context);

            assertDoesRedirectToPage(response, IPV_URI.toString());
            assertAuditEventsSubmitted(ORCH_SIS_UNSUCCESSFUL_AUTHORISATION_RESPONSE_RECEIVED);
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
            when(sisAuthorisationService.validateResponse(
                            request.getQueryStringParameters(), SESSION_ID))
                    .thenReturn(Optional.of(UPDATE_REQUESTED_ERROR));

            var response = handler.handleRequest(request, context);

            assertDoesRedirectToPage(response, IPV_URI.toString());
            assertAuditEventsSubmitted(ORCH_SIS_UNSUCCESSFUL_AUTHORISATION_RESPONSE_RECEIVED);
        }

        @Test
        void shouldRedirectToLogoutPageWhenAISInterventionOccursAfterSISErrorCheck()
                throws Exception {
            var request =
                    createRequestEvent(
                            Map.of("error", "generic_error", "error_description", "uh oh"));
            usingValidIdentityContext(request);
            when(sisAuthorisationService.validateResponse(
                            request.getQueryStringParameters(), SESSION_ID))
                    .thenReturn(Optional.of(GENERIC_ERROR));
            mockAisIntervention();

            var response = handler.handleRequest(request, context);

            assertDoesRedirectToPage(response, FRONT_END_AIS_LOGOUT_URL);
            assertAuditEventsSubmitted(ORCH_SIS_UNSUCCESSFUL_AUTHORISATION_RESPONSE_RECEIVED);
        }

        @Test
        void shouldRedirectBackToRPWithErrorWhenSISReturnsGenericErrorThatIsNotAccessDenied()
                throws Exception {
            var request =
                    createRequestEvent(
                            Map.of("error", "generic_error", "error_description", "uh oh"));
            usingValidIdentityContext(request);
            when(sisAuthorisationService.validateResponse(
                            request.getQueryStringParameters(), SESSION_ID))
                    .thenReturn(Optional.of(GENERIC_ERROR));

            var response = handler.handleRequest(request, context);

            assertDoesRedirectToPage(
                    response,
                    REDIRECT_URI
                            + "?error=access_denied"
                            + "&error_description=Access+denied+by+resource+owner+or+authorization+server"
                            + "&state="
                            + authRequestWithNoClaims.getState());
            assertAuditEventsSubmitted(ORCH_SIS_UNSUCCESSFUL_AUTHORISATION_RESPONSE_RECEIVED);
        }

        private void mockIpvRedirect(APIGatewayProxyRequestEvent request, boolean updateRequested) {
            when(ipvAuthorisationService.sendRequestToIPV(
                            eq(request),
                            eqAuthRequest(authRequestWithNoClaims),
                            eq(AUTH_USER_INFO),
                            eq(SESSION_ID),
                            eq(client),
                            eq(CLIENT_ID.getValue()),
                            eq(CLIENT_SESSION_ID),
                            eq(PERSISTENT_SESSION_ID),
                            eq(false),
                            eq(REQUESTED_LOCS.stream().map(LevelOfConfidence::getValue).toList()),
                            eq(updateRequested)))
                    .thenReturn(
                            generateApiGatewayProxyResponse(
                                    302,
                                    "",
                                    Map.of(ResponseHeaders.LOCATION, IPV_URI.toString()),
                                    null));
        }
    }

    @Test
    void shouldRedirectToErrorPageWhenTokenResponseIsUnsuccessful() throws Exception {
        var request = createRequestEvent();
        usingValidIdentityContext(request);
        mockUnsuccessfulTokenResponse();

        var response = handler.handleRequest(request, context);

        assertDoesRedirectToPage(response, FRONT_END_ERROR_URI.toString());
        assertAuditEventsSubmitted(
                ORCH_SIS_SUCCESSFUL_AUTHORISATION_RESPONSE_RECEIVED,
                ORCH_SIS_UNSUCCESSFUL_TOKEN_RESPONSE_RECEIVED);
    }

    @Nested
    class UserIdentityValidation {
        @Test
        void shouldRedirectToErrorPageWhenUserIdentityRequestTimesOut() throws Exception {
            when(identityCallbackHelper.makeTokenRequest(AUTH_CODE.getValue()))
                    .thenReturn(SUCCESSFUL_TOKEN_RESPONSE);
            when(identityCallbackHelper.sendUserIdentityRequest(
                            SUCCESSFUL_TOKEN_RESPONSE, SIS_BACKEND_URI))
                    .thenThrow(new UnsuccessfulCredentialResponseException("timed out!"));
            var request = createRequestEvent();
            usingValidIdentityContext(request);

            var response = handler.handleRequest(request, context);

            assertDoesRedirectToPage(response, FRONT_END_ERROR_URI.toString());
            assertAuditEventsSubmitted(
                    ORCH_SIS_SUCCESSFUL_AUTHORISATION_RESPONSE_RECEIVED,
                    ORCH_SIS_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED);
        }

        @Test
        void
                shouldRedirectToLogoutPageWhenAISInterventionOccursAfterUserIdentityResponseValidationFailure()
                        throws Exception {
            mockValidationFailed(new UserInfo(new Subject("sis-subject")));
            mockAisIntervention();
            var request = createRequestEvent();
            usingValidIdentityContext(request);

            var response = handler.handleRequest(request, context);
            assertDoesRedirectToPage(response, FRONT_END_AIS_LOGOUT_URL);
            assertAuditEventsSubmitted(
                    ORCH_SIS_SUCCESSFUL_AUTHORISATION_RESPONSE_RECEIVED,
                    ORCH_SIS_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED,
                    ORCH_SIS_SUCCESSFUL_IDENTITY_RESPONSE_RECEIVED);
        }

        @Test
        void
                shouldRedirectToRPWithErrorIfValidationFailedAndReturnCodeNotPresentInUserIdentityResponse()
                        throws Exception {
            mockValidationFailed(new UserInfo(new Subject("sis-subject")));
            var request = createRequestEvent();
            usingValidIdentityContext(request);

            var response = handler.handleRequest(request, context);
            assertDoesRedirectToPage(
                    response,
                    REDIRECT_URI
                            + "?error=validation_failure"
                            + "&state="
                            + authRequestWithNoClaims.getState());
            assertAuditEventsSubmitted(
                    ORCH_SIS_SUCCESSFUL_AUTHORISATION_RESPONSE_RECEIVED,
                    ORCH_SIS_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED,
                    ORCH_SIS_SUCCESSFUL_IDENTITY_RESPONSE_RECEIVED);
        }

        @Nested
        class ReturnCodeClientJourneys {
            private static final UserInfo userInfoWithReturnCode =
                    new UserInfo(
                            new JWTClaimsSet.Builder()
                                    .subject("sis-subject")
                                    .claim(RETURN_CODE.getValue(), List.of("test"))
                                    .build());
            private final AuthenticationRequest authRequestWithReturnCodeClaim =
                    generateAuthRequest(
                            new OIDCClaimsRequest()
                                    .withUserInfoClaimsRequest(
                                            new ClaimsSetRequest().add(RETURN_CODE.getValue())));
            private final ClientRegistry clientWithReturnCode =
                    new ClientRegistry()
                            .withClientID(CLIENT_ID.getValue())
                            .withClientName("test-client")
                            .withRedirectUrls(singletonList(REDIRECT_URI.toString()))
                            .withSectorIdentifierUri("https://test.com")
                            .withSubjectType("pairwise")
                            .withClaims(List.of(RETURN_CODE.getValue()));

            @Test
            void shouldRedirectBackToRPIfValidationFailedAndReturnCodeRequested() throws Exception {
                var request = createRequestEvent();
                usingIdentityContext(
                        request,
                        new IdentityContext(
                                orchSession,
                                orchClientSession.withAuthRequestParams(
                                        authRequestWithReturnCodeClaim.toParameters()),
                                clientWithReturnCode,
                                AUTH_USER_INFO,
                                authRequestWithReturnCodeClaim));
                mockValidationFailedWithReturnCodeClaim();
                mockSuccessfulAuthResponse(authRequestWithReturnCodeClaim);

                var response = handler.handleRequest(request, context);

                verify(identityCallbackHelper)
                        .saveIdentityClaimsToDynamo(
                                CLIENT_SESSION_ID,
                                new Subject(RP_PAIRWISE_SUBJECT),
                                userInfoWithReturnCode,
                                null);
                assertDoesRedirectToPage(
                        response,
                        REDIRECT_URI
                                + "?code="
                                + NEW_AUTH_CODE
                                + "&state="
                                + authRequestWithReturnCodeClaim.getState());
                assertAuditEventsSubmitted(
                        ORCH_SIS_SUCCESSFUL_AUTHORISATION_RESPONSE_RECEIVED,
                        ORCH_SIS_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED,
                        ORCH_SIS_SUCCESSFUL_IDENTITY_RESPONSE_RECEIVED,
                        AUTH_AUTH_CODE_ISSUED);
            }

            @Test
            void
                    shouldRedirectBackToRPWithErrorIfValidationFailedAndReturnCodeNotRequestedButReturnCodePresentInUserIdentityResponse()
                            throws Exception {
                var request = createRequestEvent();
                usingIdentityContext(
                        request,
                        new IdentityContext(
                                orchSession,
                                orchClientSession.withAuthRequestParams(
                                        authRequestWithNoClaims.toParameters()),
                                clientWithReturnCode,
                                AUTH_USER_INFO,
                                authRequestWithNoClaims));
                mockValidationFailedWithReturnCodeClaim();

                var response = handler.handleRequest(request, context);

                assertDoesRedirectToPage(
                        response,
                        REDIRECT_URI
                                + "?error=access_denied"
                                + "&error_description=Access+denied+by+resource+owner+or+authorization+server"
                                + "&state="
                                + authRequestWithNoClaims.getState());
                assertAuditEventsSubmitted(
                        ORCH_SIS_SUCCESSFUL_AUTHORISATION_RESPONSE_RECEIVED,
                        ORCH_SIS_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED,
                        ORCH_SIS_SUCCESSFUL_IDENTITY_RESPONSE_RECEIVED);
            }

            private void mockValidationFailedWithReturnCodeClaim() throws Exception {
                mockValidationFailed(userInfoWithReturnCode);
            }
        }

        private void mockValidationFailed(UserInfo userInfo) throws Exception {
            when(identityCallbackHelper.makeTokenRequest(AUTH_CODE.getValue()))
                    .thenReturn(SUCCESSFUL_TOKEN_RESPONSE);
            when(identityCallbackHelper.sendUserIdentityRequest(
                            SUCCESSFUL_TOKEN_RESPONSE, SIS_BACKEND_URI))
                    .thenReturn(userInfo);
            when(identityCallbackHelper.validateUserIdentityResponse(userInfo, REQUESTED_LOCS))
                    .thenReturn(Optional.of(new ErrorObject("validation_failure")));
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
                                authRequestWithNoClaims));
    }

    private void usingIdentityContext(
            APIGatewayProxyRequestEvent request, IdentityContext identityContext) throws Exception {
        when(identityContextService.buildContext(request)).thenReturn(identityContext);
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

    private void mockUnsuccessfulTokenResponse() throws IdentityCallbackException {
        when(identityCallbackHelper.makeTokenRequest(AUTH_CODE.getValue()))
                .thenThrow(new IdentityCallbackException("Token response was not successful"));
    }

    private void mockSuccessfulAuthResponse(AuthenticationRequest authRequest) {
        when(endOfJourneyService.generateSuccessfulAuthResponse(
                        eqAuthRequest(authRequest),
                        eq(CLIENT_ID.getValue()),
                        eq(CLIENT_SESSION_ID),
                        eq("test-email-address"),
                        eq(orchSession)))
                .thenReturn(
                        new AuthenticationSuccessResponse(
                                REDIRECT_URI,
                                NEW_AUTH_CODE,
                                null,
                                null,
                                authRequest.getState(),
                                null,
                                authRequest.getResponseMode()));
    }

    private void assertDoesRedirectToPage(APIGatewayProxyResponseEvent response, String page) {
        assertThat(response, hasStatus(302));
        assertEquals(page, response.getHeaders().get("Location"));
    }

    private void assertAuditEventsSubmitted(AuditableEvent... events) {
        for (var event : events) {
            verify(auditService)
                    .submitAuditEventNoPrefix(
                            eq(event), eq(CLIENT_ID.getValue()), any(TxmaAuditUser.class));
        }
        verifyNoMoreInteractions(auditService);
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

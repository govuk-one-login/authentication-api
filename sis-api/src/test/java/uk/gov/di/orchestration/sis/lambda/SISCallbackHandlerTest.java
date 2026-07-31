package uk.gov.di.orchestration.sis.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.orchestration.audit.TxmaAuditUser;
import uk.gov.di.orchestration.identity.entity.CrossBrowserNoSessionException;
import uk.gov.di.orchestration.identity.helpers.IdentityCallbackHelper;
import uk.gov.di.orchestration.identity.service.IdentityContextService;
import uk.gov.di.orchestration.shared.domain.AuditableEvent;
import uk.gov.di.orchestration.shared.entity.CrossBrowserEntity;
import uk.gov.di.orchestration.shared.entity.OrchClientSessionItem;
import uk.gov.di.orchestration.shared.exceptions.NoSessionException;
import uk.gov.di.orchestration.shared.helpers.IdGenerator;
import uk.gov.di.orchestration.shared.services.AuditService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.EndOfJourneyService;
import uk.gov.di.orchestration.shared.services.RedirectService;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;
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

    private static final URI FRONT_END_ERROR_URI = URI.create("https://example.com/error");
    private static final URI FRONT_END_SESSION_ENDED_URI =
            URI.create("https://example.com/session-ended");
    private static final AuthorizationCode AUTH_CODE = new AuthorizationCode();
    private static final String COOKIE = "Cookie";
    private static final String SESSION_ID = "a-session-id";
    private static final String CLIENT_SESSION_ID = "a-client-session-id";
    private static final String PERSISTENT_SESSION_ID = IdGenerator.generate() + "--1700558480962";
    private static final State STATE = new State();
    private static final URI REDIRECT_URI = URI.create("http://rp-redirect");
    private static final State RP_STATE = new State();
    private static final ClientID CLIENT_ID = new ClientID("test-client-id");
    private static final AuthenticationRequest NO_SESSION_AUTH_REQUEST = generateAuthRequest(null);
    private static final CrossBrowserEntity NO_SESSION_ENTITY =
            new CrossBrowserEntity(
                    "test-csid",
                    new ErrorObject("test-error", "Test Description"),
                    new OrchClientSessionItem("test-csid")
                            .withAuthRequestParams(NO_SESSION_AUTH_REQUEST.toParameters()));
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
        when(configurationService.isIdentityEnabled()).thenReturn(true);
        handler =
                new SISCallbackHandler(
                        configurationService,
                        identityCallbackHelper,
                        identityContextService,
                        auditService,
                        endOfJourneyService);
    }

    @Test
    void shouldRedirectToErrorPageWhenIdentityIsDisabled() {
        when(configurationService.isIdentityEnabled()).thenReturn(false);
        var request = createRequestEvent();

        var response = handler.handleRequest(request, context);
        assertDoesRedirectToPage(response, FRONT_END_ERROR_URI.toString());
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
                        expectedAuthRequest
                                .toParameters()
                                .equals(actualAuthRequest.toParameters()));
    }
}

package uk.gov.di.authentication.ipv.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.claims.ClaimRequirement;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.ipv.entity.IPVAuthorisationResponse;
import uk.gov.di.authentication.ipv.services.IPVAuthorisationService;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.SessionState;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SessionService;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLDecoder;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.sharedtest.helper.RequestEventHelper.contextWithSourceIp;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class IPVAuthorisationHandlerTest {

    private static final String SESSION_ID = "a-session-id";
    private static final String PERSISTENT_SESSION_ID = "a-persistent-session-id";
    private static final String TEST_CLIENT_ID = "test-client-id";
    private static final String IPV_CLIENT_ID = "ipv-client-id";

    private static final URI REDIRECT_URI = URI.create("http://localhost/oidc/redirect");
    private static final URI IPV_CALLBACK_URI = URI.create("http://localhost/oidc/ipv/callback");
    private static final URI IPV_AUTHORISATION_URI = URI.create("http://localhost/ipv");

    private static final String TEST_EMAIL_ADDRESS = "test@test.com";

    private final Context context = mock(Context.class);
    private final ConfigurationService configService = mock(ConfigurationService.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private final ClientSession clientSession = mock(ClientSession.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final ClientService clientService = mock(ClientService.class);
    private final AuditService auditService = mock(AuditService.class);
    private IPVAuthorisationService authorisationService = mock(IPVAuthorisationService.class);
    private final ClaimsSetRequest.Entry nameEntry =
            new ClaimsSetRequest.Entry("name").withClaimRequirement(ClaimRequirement.ESSENTIAL);
    private final ClaimsSetRequest.Entry birthDateEntry =
            new ClaimsSetRequest.Entry("birthdate")
                    .withClaimRequirement(ClaimRequirement.VOLUNTARY);
    private final ClaimsSetRequest claimsSetRequest =
            new ClaimsSetRequest().add(nameEntry).add(birthDateEntry);

    private IPVAuthorisationHandler handler;

    final Session session = new Session(SESSION_ID);

    @BeforeEach
    void setup() {
        handler =
                new IPVAuthorisationHandler(
                        configService,
                        sessionService,
                        clientSessionService,
                        clientService,
                        authenticationService,
                        auditService,
                        authorisationService);
        when(configService.getIPVAuthorisationClientId()).thenReturn(IPV_CLIENT_ID);
        when(configService.getIPVAuthorisationCallbackURI()).thenReturn(IPV_CALLBACK_URI);
        when(configService.getIPVAuthorisationURI()).thenReturn(IPV_AUTHORISATION_URI);
        when(configService.getSessionExpiry()).thenReturn(3600L);
    }

    @Test
    void shouldReturn200AndRedirectURIWithClaims()
            throws JsonProcessingException, UnsupportedEncodingException {

        usingValidSession();
        usingValidClientSession(TEST_CLIENT_ID);

        Map<String, String> headers = new HashMap<>();
        headers.put(PersistentIdHelper.PERSISTENT_ID_HEADER_NAME, PERSISTENT_SESSION_ID);
        headers.put("Session-Id", session.getSessionId());
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(headers);
        event.setBody(format("{ \"email\": \"%s\"}", TEST_EMAIL_ADDRESS));
        event.setRequestContext(contextWithSourceIp("123.123.123.123"));

        APIGatewayProxyResponseEvent response = makeHandlerRequest(event);

        assertThat(response, hasStatus(200));

        IPVAuthorisationResponse body =
                new ObjectMapper().readValue(response.getBody(), IPVAuthorisationResponse.class);

        assertEquals(body.getSessionState(), SessionState.IPV_REQUIRED);
        assertThat(body.getRedirectUri(), startsWith(IPV_AUTHORISATION_URI + "/authorize"));
        assertThat(
                splitQuery(body.getRedirectUri()).get("claims"),
                equalTo(claimsSetRequest.toJSONString()));
        verify(authorisationService).storeState(eq(session.getSessionId()), any(State.class));
    }

    private APIGatewayProxyResponseEvent makeHandlerRequest(APIGatewayProxyRequestEvent event) {
        var response = handler.handleRequest(event, context);

        return response;
    }

    private void usingValidSession() {
        when(sessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(session));
    }

    private void usingValidClientSession(String clientId) {
        when(clientSessionService.getClientSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(clientSession));
        when(clientSession.getAuthRequestParams())
                .thenReturn(withAuthenticationRequest(clientId).toParameters());
    }

    private AuthenticationRequest withAuthenticationRequest(String clientId) {
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        var oidcClaimsRequest = new OIDCClaimsRequest().withUserInfoClaimsRequest(claimsSetRequest);
        return new AuthenticationRequest.Builder(
                        new ResponseType(ResponseType.Value.CODE),
                        scope,
                        new ClientID(clientId),
                        REDIRECT_URI)
                .state(new State())
                .nonce(new Nonce())
                .claims(oidcClaimsRequest)
                .build();
    }

    public static Map<String, String> splitQuery(String stringUrl)
            throws UnsupportedEncodingException {
        URI uri = URI.create(stringUrl);
        Map<String, String> query_pairs = new LinkedHashMap<>();
        String query = uri.getQuery();
        String[] pairs = query.split("&");
        for (String pair : pairs) {
            int idx = pair.indexOf("=");
            query_pairs.put(
                    URLDecoder.decode(pair.substring(0, idx), "UTF-8"),
                    URLDecoder.decode(pair.substring(idx + 1), "UTF-8"));
        }
        return query_pairs;
    }
}

package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.services.AuthorizationCodeService;
import uk.gov.di.services.ClientService;
import uk.gov.di.services.TokenService;
import uk.gov.di.services.UserService;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class TokenHandlerTest {

    private final Context CONTEXT = mock(Context.class);

    private TokenHandler handler;
    private final UserInfo USER_INFO = mock(UserInfo.class);
    private final SignedJWT SIGNED_JWT = mock(SignedJWT.class);
    private final UserService USER_SERVICE = mock(UserService.class);
    private final AuthorizationCodeService AUTHORIZATION_CODE_SERVICE = mock(AuthorizationCodeService.class);
    private final TokenService TOKEN_SERVICE = mock(TokenService.class);
    private final ClientService CLIENT_SERVICE = mock(ClientService.class);

    @BeforeEach
    public void setUp() {
        handler = new TokenHandler(CLIENT_SERVICE, AUTHORIZATION_CODE_SERVICE, TOKEN_SERVICE, USER_SERVICE);
    }

    @Test
    public void shouldReturn200IfSuccessfulRequest() {
        BearerAccessToken accessToken = new BearerAccessToken();
        when(CLIENT_SERVICE.isValidClient(eq("test-id"), eq("test-secret"))).thenReturn(true);
        when(TOKEN_SERVICE.issueToken(eq("joe.bloggs@digital.cabinet-office.gov.uk"))).thenReturn(accessToken);
        when(USER_SERVICE.getInfoForEmail(eq("joe.bloggs@digital.cabinet-office.gov.uk"))).thenReturn(USER_INFO);
        when(USER_INFO.getSubject()).thenReturn(new Subject());
        when(TOKEN_SERVICE.generateIDToken(eq("test-id"), any(Subject.class))).thenReturn(SIGNED_JWT);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody("code=343242&client_id=test-id&client_secret=test-secret");
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, CONTEXT);

        assertEquals(200, result.getStatusCode());
        assertTrue(result.getBody().contains(accessToken.getValue()));
    }

    @Test
    public void shouldReturn403IfClientIsNotValid() {
        when(CLIENT_SERVICE.isValidClient(eq("invalid-id"), eq("test-secret"))).thenReturn(false);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody("code=343242&client_id=invalid-id&client_secret=test-secret");
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, CONTEXT);

        assertEquals(403, result.getStatusCode());
        assertEquals("client is not valid", result.getBody());
    }

    @Test
    public void shouldReturn400IfAnyRequestParametersAreMissing() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody("code=343242&client_id=invalid-id");
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, CONTEXT);

        assertEquals(400, result.getStatusCode());
        assertEquals("Request is missing parameters", result.getBody());

    }
}

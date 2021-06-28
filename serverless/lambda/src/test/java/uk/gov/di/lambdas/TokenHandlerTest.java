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
import uk.gov.di.services.ConfigurationService;
import uk.gov.di.services.InMemoryClientService;
import uk.gov.di.services.TokenService;
import uk.gov.di.services.UserService;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class TokenHandlerTest {

    private final Context context = mock(Context.class);
    private final UserInfo userInfo = mock(UserInfo.class);
    private final SignedJWT signedJWT = mock(SignedJWT.class);
    private final UserService userService = mock(UserService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final AuthorizationCodeService authorizationCodeService =
            mock(AuthorizationCodeService.class);
    private final TokenService tokenService = mock(TokenService.class);
    private final ClientService clientService = mock(InMemoryClientService.class);
    private TokenHandler handler;

    @BeforeEach
    public void setUp() {
        handler =
                new TokenHandler(
                        clientService,
                        authorizationCodeService,
                        tokenService,
                        userService,
                        configurationService);
    }

    @Test
    public void shouldReturn200IfSuccessfulRequest() {
        BearerAccessToken accessToken = new BearerAccessToken();
        when(clientService.isValidClient(eq("test-id"), eq("test-secret"))).thenReturn(true);
        when(tokenService.issueToken(eq("joe.bloggs@digital.cabinet-office.gov.uk")))
                .thenReturn(accessToken);
        when(userService.getInfoForEmail(eq("joe.bloggs@digital.cabinet-office.gov.uk")))
                .thenReturn(userInfo);
        when(userInfo.getSubject()).thenReturn(new Subject());
        when(tokenService.generateIDToken(eq("test-id"), any(Subject.class))).thenReturn(signedJWT);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody("code=343242&client_id=test-id&client_secret=test-secret");
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));
        assertTrue(result.getBody().contains(accessToken.getValue()));
    }

    @Test
    public void shouldReturn403IfClientIsNotValid() {
        when(clientService.isValidClient(eq("invalid-id"), eq("test-secret"))).thenReturn(false);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody("code=343242&client_id=invalid-id&client_secret=test-secret");
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(403, result.getStatusCode());
        assertThat(result, hasBody("client is not valid"));
    }

    @Test
    public void shouldReturn400IfAnyRequestParametersAreMissing() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody("code=343242&client_id=invalid-id");
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(400, result.getStatusCode());
        assertThat(result, hasBody("Request is missing parameters"));
    }
}

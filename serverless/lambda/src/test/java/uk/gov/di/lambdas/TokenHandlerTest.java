package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.entity.ErrorResponse;
import uk.gov.di.services.AuthenticationService;
import uk.gov.di.services.AuthorizationCodeService;
import uk.gov.di.services.ClientService;
import uk.gov.di.services.ConfigurationService;
import uk.gov.di.services.TokenService;

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
    private final SignedJWT signedJWT = mock(SignedJWT.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final AuthorizationCodeService authorizationCodeService =
            mock(AuthorizationCodeService.class);
    private final TokenService tokenService = mock(TokenService.class);
    private final ClientService clientService = mock(ClientService.class);
    private TokenHandler handler;

    @BeforeEach
    public void setUp() {
        handler =
                new TokenHandler(
                        clientService,
                        authorizationCodeService,
                        tokenService,
                        authenticationService,
                        configurationService);
    }

    @Test
    public void shouldReturn200IfSuccessfulRequest() {
        Subject subject = new Subject();
        BearerAccessToken accessToken = new BearerAccessToken();
        when(clientService.isValidClient(eq("test-id"))).thenReturn(true);
        when(tokenService.issueToken(eq("joe.bloggs@digital.cabinet-office.gov.uk")))
                .thenReturn(accessToken);
        when(authenticationService.getSubjectFromEmail(
                        eq("joe.bloggs@digital.cabinet-office.gov.uk")))
                .thenReturn(subject);
        when(tokenService.generateIDToken(eq("test-id"), any(Subject.class))).thenReturn(signedJWT);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody("code=343242&client_id=test-id&client_secret=test-secret");
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));
        assertTrue(result.getBody().contains(accessToken.getValue()));
    }

    @Test
    public void shouldReturn403IfClientIsNotValid() {
        when(clientService.isValidClient(eq("invalid-id"))).thenReturn(false);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody("code=343242&client_id=invalid-id&client_secret=test-secret");
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(403, result.getStatusCode());
        assertThat(result, hasBody("client is not valid"));
    }

    @Test
    public void shouldReturn400IfAnyRequestParametersAreMissing() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody("code=343242&client_id=invalid-id");
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(400, result.getStatusCode());
        String expectedResponse = new ObjectMapper().writeValueAsString(ErrorResponse.ERROR_1001);
        assertThat(result, hasBody(expectedResponse));
    }
}

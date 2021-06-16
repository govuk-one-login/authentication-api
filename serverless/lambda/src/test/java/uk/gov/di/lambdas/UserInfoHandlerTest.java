package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.LambdaLogger;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.services.TokenService;
import uk.gov.di.services.UserInfoService;

import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.matchers.APIGatewayProxyResponseEventStatusMatcher.hasStatus;

public class UserInfoHandlerTest {

    private final Context CONTEXT = mock(Context.class);

    private UserInfoHandler handler;
    private static final Optional<String> EMAIL_ADDRESS =
            Optional.of("joe.bloggs@digital.cabinet-office.gov.uk");
    private final TokenService TOKEN_SERVICE = mock(TokenService.class);
    private final UserInfoService USER_INFO_SERVICE = mock(UserInfoService.class);
    private final UserInfo USER_INFO =
            new UserInfo(new Subject()) {
                {
                    setEmailAddress(EMAIL_ADDRESS.get());
                }
            };

    @BeforeEach
    public void setUp() {
        handler = new UserInfoHandler(TOKEN_SERVICE, USER_INFO_SERVICE);
    }

    @Test
    public void shouldReturn200IfSuccessfulRequest() throws ParseException {
        when(TOKEN_SERVICE.getEmailForToken(any(BearerAccessToken.class)))
                .thenReturn(EMAIL_ADDRESS);
        when(USER_INFO_SERVICE.getInfoForEmail(eq(EMAIL_ADDRESS.get()))).thenReturn(USER_INFO);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Authorization", new BearerAccessToken().toAuthorizationHeader()));
        when(CONTEXT.getLogger()).thenReturn(mock(LambdaLogger.class));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, CONTEXT);

        assertThat(result, hasStatus(200));
        UserInfo parse = UserInfo.parse(result.getBody());
        assertEquals(EMAIL_ADDRESS.get(), parse.getEmailAddress());
    }

    @Test
    public void shouldReturn401WhenBearerTokenIsNotParseable() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Authorization", "this-is-not-a-valid-token"));
        when(CONTEXT.getLogger()).thenReturn(mock(LambdaLogger.class));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, CONTEXT);

        assertThat(result, hasStatus(401));
        assertEquals("Access Token Not Parsable", result.getBody());
    }

    @Test
    public void shouldReturn401WhenAuthorizationHeaderIsMissing() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        when(CONTEXT.getLogger()).thenReturn(mock(LambdaLogger.class));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, CONTEXT);

        assertThat(result, hasStatus(401));
        assertEquals("No access token present", result.getBody());
    }

    @Test
    public void shouldReturn401WhenAccessTokenIsNotValid() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Authorization", new BearerAccessToken().toAuthorizationHeader()));

        when(TOKEN_SERVICE.getEmailForToken(any(BearerAccessToken.class)))
                .thenReturn(Optional.empty());
        when(CONTEXT.getLogger()).thenReturn(mock(LambdaLogger.class));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, CONTEXT);

        assertThat(result, hasStatus(401));
        assertEquals("Access Token Invalid", result.getBody());
    }
}

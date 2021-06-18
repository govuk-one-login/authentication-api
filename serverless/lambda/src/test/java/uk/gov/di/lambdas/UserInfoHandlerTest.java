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
import static uk.gov.di.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class UserInfoHandlerTest {

    private static final Optional<String> EMAIL_ADDRESS =
            Optional.of("joe.bloggs@digital.cabinet-office.gov.uk");
    private final Context context = mock(Context.class);
    private final TokenService tokenService = mock(TokenService.class);
    private final UserInfoService userInfoService = mock(UserInfoService.class);
    private final UserInfo userInfo =
            new UserInfo(new Subject()) {
                {
                    setEmailAddress(EMAIL_ADDRESS.get());
                }
            };
    private UserInfoHandler handler;

    @BeforeEach
    public void setUp() {
        handler = new UserInfoHandler(tokenService, userInfoService);
    }

    @Test
    public void shouldReturn200IfSuccessfulRequest() throws ParseException {
        when(tokenService.getEmailForToken(any(BearerAccessToken.class))).thenReturn(EMAIL_ADDRESS);
        when(userInfoService.getInfoForEmail(eq(EMAIL_ADDRESS.get()))).thenReturn(userInfo);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Authorization", new BearerAccessToken().toAuthorizationHeader()));
        when(context.getLogger()).thenReturn(mock(LambdaLogger.class));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));
        UserInfo parse = UserInfo.parse(result.getBody());
        assertEquals(EMAIL_ADDRESS.get(), parse.getEmailAddress());
    }

    @Test
    public void shouldReturn401WhenBearerTokenIsNotParseable() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Authorization", "this-is-not-a-valid-token"));
        when(context.getLogger()).thenReturn(mock(LambdaLogger.class));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(401));
        assertThat(result, hasBody("Access Token Not Parsable"));
    }

    @Test
    public void shouldReturn401WhenAuthorizationHeaderIsMissing() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        when(context.getLogger()).thenReturn(mock(LambdaLogger.class));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(401));
        assertThat(result, hasBody("No access token present"));
    }

    @Test
    public void shouldReturn401WhenAccessTokenIsNotValid() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Authorization", new BearerAccessToken().toAuthorizationHeader()));

        when(tokenService.getEmailForToken(any(BearerAccessToken.class)))
                .thenReturn(Optional.empty());
        when(context.getLogger()).thenReturn(mock(LambdaLogger.class));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(401));
        assertThat(result, hasBody("Access Token Invalid"));
    }
}

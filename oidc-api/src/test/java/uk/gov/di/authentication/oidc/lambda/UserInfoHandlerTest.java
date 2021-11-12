package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.UserInfoErrorResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.oidc.services.UserInfoService;
import uk.gov.di.authentication.shared.exceptions.UserInfoValidationException;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.List;
import java.util.Map;

import static com.nimbusds.oauth2.sdk.token.BearerTokenError.INVALID_TOKEN;
import static com.nimbusds.oauth2.sdk.token.BearerTokenError.MISSING_TOKEN;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class UserInfoHandlerTest {

    private static final String EMAIL_ADDRESS = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String PHONE_NUMBER = "01234567890";
    private static final Subject SUBJECT = new Subject();
    private final Context context = mock(Context.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final UserInfoService userInfoService = mock(UserInfoService.class);
    private static final Map<String, List<String>> INVALID_TOKEN_RESPONSE =
            new UserInfoErrorResponse(INVALID_TOKEN).toHTTPResponse().getHeaderMap();
    private UserInfoHandler handler;

    @BeforeEach
    public void setUp() {
        handler = new UserInfoHandler(configurationService, userInfoService);
    }

    @Test
    public void shouldReturn200WithUserInfoBasedOnScopesForSuccessfulRequest()
            throws ParseException, UserInfoValidationException {
        AccessToken accessToken = new BearerAccessToken();
        UserInfo userInfo = new UserInfo(SUBJECT);
        userInfo.setEmailVerified(true);
        userInfo.setPhoneNumberVerified(true);
        userInfo.setPhoneNumber(PHONE_NUMBER);
        userInfo.setEmailAddress(EMAIL_ADDRESS);
        when(userInfoService.processUserInfoRequest(accessToken.toAuthorizationHeader()))
                .thenReturn(userInfo);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Authorization", accessToken.toAuthorizationHeader()));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));
        UserInfo parsedResultBody = UserInfo.parse(result.getBody());
        assertThat(parsedResultBody.getSubject(), equalTo(SUBJECT));
        assertThat(parsedResultBody.getEmailAddress(), equalTo(EMAIL_ADDRESS));
        assertTrue(parsedResultBody.getEmailVerified());
        assertThat(parsedResultBody.getPhoneNumber(), equalTo(PHONE_NUMBER));
        assertTrue(parsedResultBody.getPhoneNumberVerified());
    }

    @Test
    public void shouldReturn401WhenBearerTokenIsNotParseable() throws UserInfoValidationException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Authorization", "this-is-not-a-valid-token"));
        UserInfoValidationException userInfoValidationException =
                new UserInfoValidationException("Unable to parse AccessToken", INVALID_TOKEN);
        when(userInfoService.processUserInfoRequest("this-is-not-a-valid-token"))
                .thenThrow(userInfoValidationException);

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(401));
        assertEquals(INVALID_TOKEN_RESPONSE, result.getMultiValueHeaders());
    }

    @Test
    public void shouldReturn401WhenAuthorizationHeaderIsMissing() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(401));
        Map<String, List<String>> missingTokenExpectedResponse =
                new UserInfoErrorResponse(MISSING_TOKEN).toHTTPResponse().getHeaderMap();
        assertEquals(missingTokenExpectedResponse, result.getMultiValueHeaders());
    }
}

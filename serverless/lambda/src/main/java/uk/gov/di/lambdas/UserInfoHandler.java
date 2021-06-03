package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.LambdaLogger;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import uk.gov.di.services.InMemoryUserInfoService;
import uk.gov.di.services.TokenService;
import uk.gov.di.services.UserInfoService;

import java.util.NoSuchElementException;

public class UserInfoHandler implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final TokenService tokenService;
    private final UserInfoService userInfoService;

    public UserInfoHandler(TokenService tokenService, UserInfoService userInfoService) {
        this.tokenService = tokenService;
        this.userInfoService = userInfoService;
    }

    public UserInfoHandler() {
        tokenService = new TokenService();
        userInfoService = new InMemoryUserInfoService();
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(APIGatewayProxyRequestEvent input, Context context) {
        LambdaLogger logger = context.getLogger();
        APIGatewayProxyResponseEvent apiGatewayProxyResponseEvent = new APIGatewayProxyResponseEvent();

        try {
            AccessToken accessToken = AccessToken.parse(input.getHeaders().get("Authorization"));
            logger.log("Access Token = " + accessToken.getValue());

            String emailForToken = tokenService.getEmailForToken(accessToken).orElseThrow();
            UserInfo userInfo = userInfoService.getInfoForEmail(emailForToken);

            apiGatewayProxyResponseEvent.setStatusCode(200);
            apiGatewayProxyResponseEvent.setBody(userInfo.toJSONString());

            return apiGatewayProxyResponseEvent;
        } catch (ParseException e) {
            logger.log("Access Token Not Parsable");

            apiGatewayProxyResponseEvent.setStatusCode(401);
            apiGatewayProxyResponseEvent.setBody("Access Token Not Parsable");

            return apiGatewayProxyResponseEvent;
        } catch (NullPointerException e) {
            logger.log("Access Token Not Present");

            apiGatewayProxyResponseEvent.setStatusCode(401);
            apiGatewayProxyResponseEvent.setBody("No access token present");

            return apiGatewayProxyResponseEvent;
        } catch (NoSuchElementException e) {
            logger.log("Access Token Invalid");

            apiGatewayProxyResponseEvent.setStatusCode(401);
            apiGatewayProxyResponseEvent.setBody("Access Token Invalid");

            return apiGatewayProxyResponseEvent;

        }
    }
}

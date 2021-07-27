package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.services.ConfigurationService;
import uk.gov.di.services.InMemoryUserInfoService;
import uk.gov.di.services.RedisConnectionService;
import uk.gov.di.services.TokenService;
import uk.gov.di.services.UserInfoService;

import java.util.NoSuchElementException;

import static uk.gov.di.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;

public class UserInfoHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER = LoggerFactory.getLogger(UserInfoHandler.class);

    private final TokenService tokenService;
    private final UserInfoService userInfoService;
    private final ConfigurationService configurationService;

    public UserInfoHandler(
            TokenService tokenService,
            UserInfoService userInfoService,
            ConfigurationService configurationService) {
        this.tokenService = tokenService;
        this.userInfoService = userInfoService;
        this.configurationService = configurationService;
    }

    public UserInfoHandler() {
        configurationService = new ConfigurationService();
        tokenService =
                new TokenService(
                        configurationService, new RedisConnectionService(configurationService));
        userInfoService = new InMemoryUserInfoService();
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {

        try {
            AccessToken accessToken = AccessToken.parse(input.getHeaders().get("Authorization"));
            LOGGER.info("Access Token = {}", accessToken.getValue());

            String emailForToken = tokenService.getEmailForToken(accessToken).orElseThrow();
            UserInfo userInfo = userInfoService.getInfoForEmail(emailForToken);

            return generateApiGatewayProxyResponse(200, userInfo.toJSONString());
        } catch (ParseException e) {
            LOGGER.error("Access Token Not Parsable");

            return generateApiGatewayProxyResponse(401, "Access Token Not Parsable");
        } catch (NullPointerException e) {
            LOGGER.error("Access Token Not Present");

            return generateApiGatewayProxyResponse(401, "No access token present");
        } catch (NoSuchElementException e) {
            LOGGER.error("Access Token Invalid");

            return generateApiGatewayProxyResponse(401, "Access Token Invalid");
        }
    }
}

package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.openid.connect.sdk.UserInfoErrorResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.authentication.oidc.services.UserInfoService;
import uk.gov.di.authentication.shared.exceptions.UserInfoValidationException;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoClientService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.TokenValidationService;

import static com.nimbusds.oauth2.sdk.token.BearerTokenError.MISSING_TOKEN;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.WarmerHelper.isWarming;

public class UserInfoHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER = LoggerFactory.getLogger(UserInfoHandler.class);
    private final ConfigurationService configurationService;
    private final UserInfoService userInfoService;

    public UserInfoHandler(
            ConfigurationService configurationService, UserInfoService userInfoService) {
        this.configurationService = configurationService;
        this.userInfoService = userInfoService;
    }

    public UserInfoHandler() {
        configurationService = ConfigurationService.getInstance();
        RedisConnectionService redisConnectionService =
                new RedisConnectionService(configurationService);
        userInfoService =
                new UserInfoService(
                        redisConnectionService,
                        new DynamoService(
                                configurationService.getAwsRegion(),
                                configurationService.getEnvironment(),
                                configurationService.getDynamoEndpointUri()),
                        new TokenValidationService(
                                configurationService,
                                new KmsConnectionService(configurationService)),
                        new DynamoClientService(
                                configurationService.getAwsRegion(),
                                configurationService.getEnvironment(),
                                configurationService.getDynamoEndpointUri()));
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return isWarming(input)
                .orElseGet(
                        () -> {
                            LOGGER.info("Request received to the UserInfoHandler");
                            if (input.getHeaders() == null
                                    || !input.getHeaders().containsKey("Authorization")
                                    || input.getHeaders().get("Authorization").isEmpty()) {
                                LOGGER.error("AccessToken is missing from request");
                                return generateApiGatewayProxyResponse(
                                        401,
                                        "",
                                        new UserInfoErrorResponse(MISSING_TOKEN)
                                                .toHTTPResponse()
                                                .getHeaderMap());
                            }
                            UserInfo userInfo;
                            try {
                                userInfo =
                                        userInfoService.processUserInfoRequest(
                                                input.getHeaders().get("Authorization"));
                            } catch (UserInfoValidationException e) {
                                LOGGER.error(
                                        "UserInfoValidationException. Sending back UserInfoErrorResponse");
                                return generateApiGatewayProxyResponse(
                                        401,
                                        "",
                                        new UserInfoErrorResponse(e.getError())
                                                .toHTTPResponse()
                                                .getHeaderMap());
                            }
                            LOGGER.info(
                                    "Successfully processed UserInfo request. Sending back UserInfo response");
                            return generateApiGatewayProxyResponse(200, userInfo.toJSONString());
                        });
    }
}

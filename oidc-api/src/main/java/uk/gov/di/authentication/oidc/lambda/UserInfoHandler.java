package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.openid.connect.sdk.UserInfoErrorResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.app.services.DynamoDocAppService;
import uk.gov.di.authentication.oidc.entity.AccessTokenInfo;
import uk.gov.di.authentication.oidc.services.AccessTokenService;
import uk.gov.di.authentication.oidc.services.UserInfoService;
import uk.gov.di.authentication.shared.exceptions.AccessTokenException;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoClientService;
import uk.gov.di.authentication.shared.services.DynamoIdentityService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.JwksService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.TokenValidationService;

import static com.nimbusds.oauth2.sdk.token.BearerTokenError.MISSING_TOKEN;
import static uk.gov.di.authentication.shared.domain.RequestHeaders.AUTHORIZATION_HEADER;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.authentication.shared.helpers.RequestHeaderHelper.getHeaderValueFromHeaders;
import static uk.gov.di.authentication.shared.helpers.RequestHeaderHelper.headersContainValidHeader;
import static uk.gov.di.authentication.shared.helpers.WarmerHelper.isWarming;

public class UserInfoHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(UserInfoHandler.class);
    private final ConfigurationService configurationService;
    private final UserInfoService userInfoService;
    private final AccessTokenService accessTokenService;

    public UserInfoHandler(
            ConfigurationService configurationService,
            UserInfoService userInfoService,
            AccessTokenService accessTokenService) {
        this.configurationService = configurationService;
        this.userInfoService = userInfoService;
        this.accessTokenService = accessTokenService;
    }

    public UserInfoHandler() {
        this(ConfigurationService.getInstance());
    }

    public UserInfoHandler(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.userInfoService =
                new UserInfoService(
                        new DynamoService(configurationService),
                        new DynamoIdentityService(configurationService),
                        new DynamoDocAppService(configurationService),
                        new CloudwatchMetricsService(),
                        configurationService);
        this.accessTokenService =
                new AccessTokenService(
                        new RedisConnectionService(configurationService),
                        new DynamoClientService(configurationService),
                        new TokenValidationService(
                                new JwksService(
                                        configurationService,
                                        new KmsConnectionService(configurationService))));
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return segmentedFunctionCall(
                "oidc-api::" + getClass().getSimpleName(),
                () -> userInfoRequestHandler(input, context));
    }

    public APIGatewayProxyResponseEvent userInfoRequestHandler(
            APIGatewayProxyRequestEvent input, Context context) {
        return isWarming(input)
                .orElseGet(
                        () -> {
                            LOG.info("Request received to the UserInfoHandler");
                            if (!headersContainValidHeader(
                                    input.getHeaders(),
                                    AUTHORIZATION_HEADER,
                                    configurationService.getHeadersCaseInsensitive())) {
                                LOG.warn("AccessToken is missing from request");
                                return generateApiGatewayProxyResponse(
                                        401,
                                        "",
                                        new UserInfoErrorResponse(MISSING_TOKEN)
                                                .toHTTPResponse()
                                                .getHeaderMap());
                            }
                            UserInfo userInfo;
                            try {
                                AccessTokenInfo accessTokenInfo =
                                        accessTokenService.parse(
                                                getHeaderValueFromHeaders(
                                                        input.getHeaders(),
                                                        AUTHORIZATION_HEADER,
                                                        configurationService
                                                                .getHeadersCaseInsensitive()),
                                                configurationService.isIdentityEnabled());
                                userInfo = userInfoService.populateUserInfo(accessTokenInfo);
                            } catch (AccessTokenException e) {
                                LOG.warn(
                                        "AccessTokenException. Sending back UserInfoErrorResponse");
                                return generateApiGatewayProxyResponse(
                                        401,
                                        "",
                                        new UserInfoErrorResponse(e.getError())
                                                .toHTTPResponse()
                                                .getHeaderMap());
                            }
                            LOG.info(
                                    "Successfully processed UserInfo request. Sending back UserInfo response");
                            return generateApiGatewayProxyResponse(200, userInfo.toJSONString());
                        });
    }
}

package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;
import com.nimbusds.openid.connect.sdk.UserInfoErrorResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.TokenValidationService;

import java.util.Map;
import java.util.Optional;

import static com.nimbusds.oauth2.sdk.token.BearerTokenError.INVALID_TOKEN;
import static com.nimbusds.oauth2.sdk.token.BearerTokenError.MISSING_TOKEN;
import static java.lang.String.format;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.validateScopesAndRetrieveUserInfo;
import static uk.gov.di.authentication.shared.helpers.WarmerHelper.isWarming;

public class UserInfoHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER = LoggerFactory.getLogger(UserInfoHandler.class);

    private final RedisConnectionService redisConnectionService;
    private final ConfigurationService configurationService;
    private final AuthenticationService authenticationService;
    private final TokenValidationService tokenValidationService;

    public UserInfoHandler(
            ConfigurationService configurationService,
            AuthenticationService authenticationService,
            RedisConnectionService redisConnectionService,
            TokenValidationService tokenValidationService) {
        this.configurationService = configurationService;
        this.authenticationService = authenticationService;
        this.redisConnectionService = redisConnectionService;
        this.tokenValidationService = tokenValidationService;
    }

    public UserInfoHandler() {
        configurationService = new ConfigurationService();
        authenticationService =
                new DynamoService(
                        configurationService.getAwsRegion(),
                        configurationService.getEnvironment(),
                        configurationService.getDynamoEndpointUri());
        redisConnectionService = new RedisConnectionService(configurationService);
        this.tokenValidationService =
                new TokenValidationService(
                        configurationService,
                        redisConnectionService,
                        new KmsConnectionService(configurationService));
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return isWarming(input)
                .orElseGet(
                        () -> {
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
                            AccessToken accessToken;
                            try {
                                accessToken =
                                        AccessToken.parse(
                                                input.getHeaders().get("Authorization"),
                                                AccessTokenType.BEARER);
                            } catch (Exception e) {
                                LOGGER.error(
                                        format(
                                                "Unable to parse AccessToken with headers: %s.\n\n Exception thrown: %s",
                                                input.getHeaders(), e));
                                return generateApiGatewayProxyResponse(
                                        401,
                                        "",
                                        new UserInfoErrorResponse(INVALID_TOKEN)
                                                .toHTTPResponse()
                                                .getHeaderMap());
                            }
                            if (!tokenValidationService.validateAccessTokenSignature(accessToken)) {
                                LOGGER.error("Unable to validate AccessToken signature");
                                return generateApiGatewayProxyResponse(
                                        401,
                                        "",
                                        new UserInfoErrorResponse(INVALID_TOKEN)
                                                .toHTTPResponse()
                                                .getHeaderMap());
                            }
                            Optional<String> subjectFromAccessToken =
                                    getSubjectWithAccessToken(accessToken);

                            return subjectFromAccessToken
                                    .map(
                                            t ->
                                                    validateScopesAndRetrieveUserInfo(
                                                            t,
                                                            accessToken,
                                                            authenticationService,
                                                            input.getHeaders()))
                                    .orElse(generateErrorResponse(input.getHeaders()));
                        });
    }

    private APIGatewayProxyResponseEvent generateErrorResponse(Map<String, String> headers) {
        LOGGER.error(
                format(
                        "Encountered an error while validating scope and retrieving user info for AccessToken with headers: %s.",
                        headers));

        return generateApiGatewayProxyResponse(
                401, "", new UserInfoErrorResponse(INVALID_TOKEN).toHTTPResponse().getHeaderMap());
    }

    private Optional<String> getSubjectWithAccessToken(AccessToken token) {
        return Optional.ofNullable(redisConnectionService.getValue(token.toJSONString()));
    }
}

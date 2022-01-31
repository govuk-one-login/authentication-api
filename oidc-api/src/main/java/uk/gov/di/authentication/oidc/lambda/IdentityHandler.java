package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.oidc.entity.IdentityErrorResponse;
import uk.gov.di.authentication.oidc.entity.IdentityResponse;
import uk.gov.di.authentication.oidc.services.AccessTokenService;
import uk.gov.di.authentication.oidc.services.IdentityService;
import uk.gov.di.authentication.shared.exceptions.AccessTokenException;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoClientService;
import uk.gov.di.authentication.shared.services.DynamoSpotService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.TokenValidationService;

import static com.nimbusds.oauth2.sdk.token.BearerTokenError.MISSING_TOKEN;
import static uk.gov.di.authentication.shared.domain.RequestHeaders.AUTHORIZATION_HEADER;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.RequestHeaderHelper.getHeaderValueFromHeaders;
import static uk.gov.di.authentication.shared.helpers.RequestHeaderHelper.headersContainValidHeader;
import static uk.gov.di.authentication.shared.helpers.WarmerHelper.isWarming;

public class IdentityHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(IdentityHandler.class);
    private final ConfigurationService configurationService;
    private final AccessTokenService accessTokenService;
    private final IdentityService identityService;

    public IdentityHandler() {
        this(ConfigurationService.getInstance());
    }

    public IdentityHandler(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.accessTokenService =
                new AccessTokenService(
                        new RedisConnectionService(configurationService),
                        new DynamoClientService(configurationService),
                        new TokenValidationService(
                                configurationService,
                                new KmsConnectionService(configurationService)));
        this.identityService = new IdentityService(new DynamoSpotService(configurationService));
    }

    public IdentityHandler(
            ConfigurationService configurationService,
            AccessTokenService accessTokenService,
            IdentityService identityService) {
        this.configurationService = configurationService;
        this.accessTokenService = accessTokenService;
        this.identityService = identityService;
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return isWarming(input)
                .orElseGet(
                        () -> {
                            LOG.info("Request received to the IdentityHandler");
                            if (!headersContainValidHeader(
                                    input.getHeaders(),
                                    AUTHORIZATION_HEADER,
                                    configurationService.getHeadersCaseInsensitive())) {
                                LOG.error("AccessToken is missing from request");
                                return generateApiGatewayProxyResponse(
                                        401,
                                        "",
                                        new IdentityErrorResponse(MISSING_TOKEN)
                                                .toHTTPResponse()
                                                .getHeaderMap());
                            }
                            IdentityResponse identityResponse;
                            try {
                                var accessTokenInfo =
                                        accessTokenService.parse(
                                                getHeaderValueFromHeaders(
                                                        input.getHeaders(),
                                                        AUTHORIZATION_HEADER,
                                                        configurationService
                                                                .getHeadersCaseInsensitive()),
                                                true);
                                identityResponse =
                                        identityService.populateIdentityResponse(accessTokenInfo);
                            } catch (AccessTokenException e) {
                                LOG.error(
                                        "AccessTokenException. Sending back IdentityErrorResponse");
                                return generateApiGatewayProxyResponse(
                                        401,
                                        "",
                                        new IdentityErrorResponse(e.getError())
                                                .toHTTPResponse()
                                                .getHeaderMap());
                            }
                            LOG.info(
                                    "Successfully processed Identity request. Sending back Identity response");
                            try {
                                return generateApiGatewayProxyResponse(200, identityResponse);
                            } catch (JsonProcessingException e) {
                                LOG.error("Unable to searlize the IdentityResponse");
                                throw new RuntimeException(e);
                            }
                        });
    }
}

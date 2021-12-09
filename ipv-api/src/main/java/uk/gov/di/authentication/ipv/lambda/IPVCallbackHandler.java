package uk.gov.di.authentication.ipv.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import org.apache.http.client.utils.URIBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.ipv.services.AuthorisationResponseService;
import uk.gov.di.authentication.ipv.services.IPVTokenService;
import uk.gov.di.authentication.shared.entity.ResponseHeaders;
import uk.gov.di.authentication.shared.helpers.CookieHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;

import java.net.URISyntaxException;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Optional;

import static uk.gov.di.authentication.shared.helpers.WarmerHelper.isWarming;

public class IPVCallbackHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(IPVCallbackHandler.class);
    private final ConfigurationService configurationService;
    private final AuthorisationResponseService responseService;
    private final IPVTokenService ipvTokenService;

    public IPVCallbackHandler() {
        this(ConfigurationService.getInstance());
    }

    public IPVCallbackHandler(
            ConfigurationService configurationService,
            AuthorisationResponseService responseService,
            IPVTokenService ipvTokenService) {
        this.configurationService = configurationService;
        this.responseService = responseService;
        this.ipvTokenService = ipvTokenService;
    }

    public IPVCallbackHandler(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.responseService =
                new AuthorisationResponseService(
                        configurationService, new RedisConnectionService(configurationService));
        this.ipvTokenService =
                new IPVTokenService(
                        configurationService, new RedisConnectionService(configurationService));
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return isWarming(input)
                .orElseGet(
                        () -> {
                            LOG.info("Request received to IPVCallbackHandler");
                            Optional<ErrorObject> errorObject =
                                    responseService.validateResponse(
                                            input.getQueryStringParameters());
                            if (errorObject.isPresent()) {
                                LOG.error(
                                        "Error in IPV AuthorisationResponse. ErrorCode: {}. ErrorDescription: {}",
                                        errorObject.get().getCode(),
                                        errorObject.get().getDescription());
                                throw new RuntimeException("Error in IPV AuthorisationResponse");
                            }
                            CookieHelper.SessionCookieIds sessionCookieIds;
                            try {
                                sessionCookieIds =
                                        CookieHelper.parseSessionCookie(input.getHeaders())
                                                .orElseThrow();
                            } catch (NoSuchElementException e) {
                                LOG.error("SessionID not found in cookie");
                                throw new RuntimeException(e);
                            }
                            TokenRequest tokenRequest =
                                    ipvTokenService.constructTokenRequest(
                                            input.getQueryStringParameters().get("code"));
                            TokenResponse tokenResponse =
                                    ipvTokenService.sendTokenRequest(tokenRequest);
                            if (!tokenResponse.indicatesSuccess()) {
                                LOG.error(
                                        "IPV TokenResponse was not successful: {}",
                                        tokenResponse.toErrorResponse().toJSONObject());
                                throw new RuntimeException("IPV TokenResponse was not successful");
                            }
                            ipvTokenService.saveAccessTokenToRedis(
                                    tokenResponse.toSuccessResponse().getTokens().getAccessToken(),
                                    sessionCookieIds.getSessionId());

                            return new APIGatewayProxyResponseEvent()
                                    .withStatusCode(302)
                                    .withHeaders(
                                            Map.of(ResponseHeaders.LOCATION, buildRedirectUri()));
                        });
    }

    private String buildRedirectUri() {
        URIBuilder redirectUriBuilder = new URIBuilder(configurationService.getLoginURI());
        try {
            return redirectUriBuilder.build().toString();
        } catch (URISyntaxException e) {
            throw new RuntimeException();
        }
    }
}

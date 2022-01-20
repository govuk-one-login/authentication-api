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
import uk.gov.di.authentication.ipv.services.IPVAuthorisationService;
import uk.gov.di.authentication.ipv.services.IPVTokenService;
import uk.gov.di.authentication.shared.entity.ResponseHeaders;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.SessionService;

import java.net.URISyntaxException;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Optional;

import static uk.gov.di.authentication.shared.helpers.WarmerHelper.isWarming;

public class IPVCallbackHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(IPVCallbackHandler.class);
    private final ConfigurationService configurationService;
    private final IPVAuthorisationService ipvAuthorisationService;
    private final IPVTokenService ipvTokenService;
    private final SessionService sessionService;
    private final DynamoService dynamoService;
    private static final String REDIRECT_PATH = "auth-code";

    public IPVCallbackHandler() {
        this(ConfigurationService.getInstance());
    }

    public IPVCallbackHandler(
            ConfigurationService configurationService,
            IPVAuthorisationService responseService,
            IPVTokenService ipvTokenService,
            SessionService sessionService,
            DynamoService dynamoService) {
        this.configurationService = configurationService;
        this.ipvAuthorisationService = responseService;
        this.ipvTokenService = ipvTokenService;
        this.sessionService = sessionService;
        this.dynamoService = dynamoService;
    }

    public IPVCallbackHandler(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.ipvAuthorisationService =
                new IPVAuthorisationService(
                        configurationService, new RedisConnectionService(configurationService));
        this.ipvTokenService = new IPVTokenService(configurationService);
        this.sessionService = new SessionService(configurationService);
        this.dynamoService = new DynamoService(configurationService);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return isWarming(input)
                .orElseGet(
                        () -> {
                            LOG.info("Request received to IPVCallbackHandler");
                            Session session;
                            try {
                                session =
                                        sessionService
                                                .getSessionFromSessionCookie(input.getHeaders())
                                                .orElseThrow();
                            } catch (NoSuchElementException e) {
                                LOG.error("Session not found");
                                throw new RuntimeException("Session not found", e);
                            }
                            Optional<ErrorObject> errorObject =
                                    ipvAuthorisationService.validateResponse(
                                            input.getQueryStringParameters(),
                                            session.getSessionId());
                            if (errorObject.isPresent()) {
                                LOG.error(
                                        "Error in IPV AuthorisationResponse. ErrorCode: {}. ErrorDescription: {}",
                                        errorObject.get().getCode(),
                                        errorObject.get().getDescription());
                                throw new RuntimeException("Error in IPV AuthorisationResponse");
                            }
                            Optional<UserProfile> userProfile =
                                    dynamoService.getUserProfileFromEmail(
                                            session.getEmailAddress());
                            if (userProfile.isEmpty()) {
                                LOG.error("Email from session does not have a user profile");
                                throw new RuntimeException(
                                        "Email from session does not have a user profile");
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

                            return new APIGatewayProxyResponseEvent()
                                    .withStatusCode(302)
                                    .withHeaders(
                                            Map.of(ResponseHeaders.LOCATION, buildRedirectUri()));
                        });
    }

    private String buildRedirectUri() {
        URIBuilder redirectUriBuilder =
                new URIBuilder(configurationService.getLoginURI()).setPath(REDIRECT_PATH);
        try {
            return redirectUriBuilder.build().toString();
        } catch (URISyntaxException e) {
            throw new RuntimeException();
        }
    }
}

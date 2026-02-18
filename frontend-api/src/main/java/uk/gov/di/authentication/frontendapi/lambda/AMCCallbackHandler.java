package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.frontendapi.entity.AMCCallbackRequest;
import uk.gov.di.authentication.frontendapi.services.AMCService;
import uk.gov.di.authentication.frontendapi.services.JwtService;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.lambda.BaseFrontendHandler;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.io.IOException;
import java.time.Clock;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;

public class AMCCallbackHandler extends BaseFrontendHandler<AMCCallbackRequest>
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private final AMCService amcService;

    private static final Logger LOG = LogManager.getLogger(AMCCallbackHandler.class);

    public AMCCallbackHandler() {
        this(ConfigurationService.getInstance());
    }

    public AMCCallbackHandler(ConfigurationService configurationService) {
        super(AMCCallbackRequest.class, configurationService, true);
        this.amcService =
                new AMCService(
                        configurationService,
                        new NowHelper.NowClock(Clock.systemUTC()),
                        new JwtService(new KmsConnectionService(configurationService)));
    }

    public AMCCallbackHandler(
            ConfigurationService configurationService,
            AuthenticationService authenticationService,
            AuthSessionService authSessionService,
            AMCService amcService) {
        super(
                AMCCallbackRequest.class,
                configurationService,
                authenticationService,
                authSessionService);
        this.amcService = amcService;
    }

    @SuppressWarnings("java:S1185")
    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return super.handleRequest(input, context);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequestWithUserContext(
            APIGatewayProxyRequestEvent input,
            Context context,
            AMCCallbackRequest request,
            UserContext userContext) {

        LOG.info("Request received to AMCCallbackHandler");

        var requestResult = amcService.buildTokenRequest(request.code());

        return requestResult
                .map(tokenRequest -> sendTokenRequest(tokenRequest))
                .fold(
                        failure -> generateApiGatewayProxyResponse(500, "todo"),
                        tokenResponse -> generateApiGatewayProxyResponse(200, "very cool"));
    }

    private TokenResponse sendTokenRequest(TokenRequest tokenRequest) {
        try {
            var response = tokenRequest.toHTTPRequest().send();
            return TokenResponse.parse(response);
        } catch (IOException e) {
            throw new RuntimeException("TODO");
        } catch (ParseException e) {
            throw new RuntimeException("TODO");
        }
    }
}

package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.yubico.webauthn.RelyingParty;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.frontendapi.entity.FinishPasskeyAssertionRequest;
import uk.gov.di.authentication.frontendapi.services.webauthn.RelyingPartyProvider;
import uk.gov.di.authentication.shared.lambda.BaseFrontendHandler;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.state.UserContext;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;

public class FinishPasskeyAssertionHandler
        extends BaseFrontendHandler<FinishPasskeyAssertionRequest>
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private static final Logger LOG = LogManager.getLogger(FinishPasskeyAssertionHandler.class);
    private final RelyingParty relyingParty;

    public FinishPasskeyAssertionHandler() {
        this(ConfigurationService.getInstance());
    }

    public FinishPasskeyAssertionHandler(
            ConfigurationService configurationService,
            AuthenticationService authenticationService,
            AuthSessionService authSessionService,
            RelyingParty relyingParty) {
        super(
                FinishPasskeyAssertionRequest.class,
                configurationService,
                authenticationService,
                authSessionService);
        this.relyingParty = relyingParty;
    }

    public FinishPasskeyAssertionHandler(ConfigurationService configurationService) {
        super(FinishPasskeyAssertionRequest.class, configurationService);
        this.relyingParty = RelyingPartyProvider.provide(configurationService);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return super.handleRequest(input, context);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequestWithUserContext(
            APIGatewayProxyRequestEvent input,
            Context context,
            FinishPasskeyAssertionRequest request,
            UserContext userContext) {
        LOG.info("FinishPasskeyAssertionHandler called");
        return generateApiGatewayProxyResponse(200, "");
    }
}

package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.yubico.webauthn.AssertionResult;
import com.yubico.webauthn.exception.AssertionFailedException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.frontendapi.entity.FinishPasskeyAssertionRequest;
import uk.gov.di.authentication.frontendapi.services.webauthn.DefaultPasskeyJsonParser;
import uk.gov.di.authentication.frontendapi.services.webauthn.PasskeyAssertionService;
import uk.gov.di.authentication.frontendapi.services.webauthn.RelyingPartyProvider;
import uk.gov.di.authentication.shared.lambda.BaseFrontendHandler;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.io.IOException;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;

public class FinishPasskeyAssertionHandler
        extends BaseFrontendHandler<FinishPasskeyAssertionRequest>
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private static final Logger LOG = LogManager.getLogger(FinishPasskeyAssertionHandler.class);
    private final PasskeyAssertionService passkeyAssertionService;

    public FinishPasskeyAssertionHandler() {
        this(ConfigurationService.getInstance());
    }

    public FinishPasskeyAssertionHandler(
            ConfigurationService configurationService,
            AuthenticationService authenticationService,
            AuthSessionService authSessionService,
            PasskeyAssertionService passkeyAssertionService) {
        super(
                FinishPasskeyAssertionRequest.class,
                configurationService,
                authenticationService,
                authSessionService);
        this.passkeyAssertionService = passkeyAssertionService;
    }

    public FinishPasskeyAssertionHandler(ConfigurationService configurationService) {
        super(FinishPasskeyAssertionRequest.class, configurationService);
        this.passkeyAssertionService =
                new PasskeyAssertionService(
                        RelyingPartyProvider.provide(configurationService),
                        new DefaultPasskeyJsonParser());
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

        try {
            AssertionResult result =
                    passkeyAssertionService.finishAssertion(
                            userContext.getAuthSession().getPasskeyAssertionRequest(),
                            request.pkc());

            if (!result.isSuccess()) {
                return generateApiGatewayProxyResponse(401, "Failed authenticating with passkey");
            }

            return generateApiGatewayProxyResponse(200, "");
        } catch (IOException e) {
            // TODO - AUT-4938 - There are different IOExceptions that might happen depending on
            // whether the assertionRequest or pkc failed
            LOG.error("Error deserializing JSON");
            return generateApiGatewayProxyResponse(400, "Bad request");
        } catch (AssertionFailedException e) {
            LOG.error("Error validating assertion", e);
            return generateApiGatewayProxyResponse(
                    500, "Internal server error validating assertion");
        }

        // TODO - AUT-4938 - Double-check response codes are suitable
        // TODO - AUT-4938 - Update database with latest passkey values
    }
}

package uk.gov.di.authentication.clientregistry.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.authentication.clientregistry.entity.ClientInfoResponse;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.lambda.UserContextAwareHandler;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SessionService;

import java.util.List;
import java.util.Map;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.WarmerHelper.isWarming;

public class ClientInfoHandler extends UserContextAwareHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER = LoggerFactory.getLogger(ClientInfoHandler.class);

    public ClientInfoHandler(
            ConfigurationService configurationService,
            ClientSessionService clientSessionService,
            ClientService clientService,
            SessionService sessionService) {
        super(configurationService, sessionService, clientSessionService, clientService);
    }

    public ClientInfoHandler() {
        super();
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return isWarming(input)
                .orElseGet(
                        () ->
                                initializeUserContext(input.getHeaders(), true)
                                        .orElseGet(() -> handleRequestDelegate(input, context)));
    }

    @Override
    protected APIGatewayProxyResponseEvent handleRequestDelegate(
            APIGatewayProxyRequestEvent input, Context context) {
        try {
            Map<String, List<String>> authRequest = getClientSession().getAuthRequestParams();

            String state = null;
            if (AuthenticationRequest.parse(authRequest).getState() != null) {
                state = AuthenticationRequest.parse(authRequest).getState().getValue();
            }
            String redirectUri = null;
            if (AuthenticationRequest.parse(authRequest).getRedirectionURI() != null) {
                redirectUri =
                        AuthenticationRequest.parse(authRequest).getRedirectionURI().toString();
            }

            ClientRegistry clientRegistry = getClientRegistry();
            ClientInfoResponse clientInfoResponse =
                    new ClientInfoResponse(
                            clientRegistry.getClientID(),
                            clientRegistry.getClientName(),
                            clientRegistry.getScopes(),
                            redirectUri,
                            clientRegistry.getServiceType(),
                            state);

            LOGGER.info(
                    "Found Client Info for ClientID: {} ClientName {} Scopes {} Redirect Uri {} Service Type {} State {}",
                    clientRegistry.getClientID(),
                    clientRegistry.getClientName(),
                    clientRegistry.getScopes(),
                    redirectUri,
                    clientRegistry.getServiceType(),
                    state);

            return generateApiGatewayProxyResponse(200, clientInfoResponse);

        } catch (ParseException | JsonProcessingException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        }
    }
}

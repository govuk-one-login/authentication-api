package uk.gov.di.authentication.app.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.app.entity.DocAppAuthorisationResponse;
import uk.gov.di.authentication.app.services.DocAppAuthorisationService;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.SessionService;

import java.util.Objects;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachSessionIdToLogs;
import static uk.gov.di.authentication.shared.helpers.WarmerHelper.isWarming;

public class DocAppAuthorizeHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(DocAppAuthorizeHandler.class);

    private final SessionService sessionService;
    private final ClientSessionService clientSessionService;
    private final DocAppAuthorisationService authorisationService;
    private final ConfigurationService configurationService;

    public DocAppAuthorizeHandler() {
        this(ConfigurationService.getInstance());
    }

    public DocAppAuthorizeHandler(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.sessionService = new SessionService(configurationService);
        this.clientSessionService = new ClientSessionService(configurationService);
        this.authorisationService =
                new DocAppAuthorisationService(
                        configurationService,
                        new RedisConnectionService(configurationService),
                        new KmsConnectionService(configurationService));
    }

    public DocAppAuthorizeHandler(
            SessionService sessionService,
            ClientSessionService clientSessionService,
            DocAppAuthorisationService authorisationService,
            ConfigurationService configurationService) {
        this.sessionService = sessionService;
        this.clientSessionService = clientSessionService;
        this.authorisationService = authorisationService;
        this.configurationService = configurationService;
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return isWarming(input)
                .orElseGet(
                        () -> {
                            try {
                                LOG.info("DocAppAuthorizeHandler received request");

                                var session =
                                        sessionService
                                                .getSessionFromRequestHeaders(input.getHeaders())
                                                .orElse(null);
                                var clientSession =
                                        clientSessionService
                                                .getClientSessionFromRequestHeaders(
                                                        input.getHeaders())
                                                .orElse(null);
                                if (Objects.isNull(session)) {
                                    LOG.warn("Session cannot be found");
                                    return generateApiGatewayProxyErrorResponse(
                                            400, ErrorResponse.ERROR_1000);
                                }
                                if (Objects.isNull(clientSession)) {
                                    LOG.warn("ClientSession cannot be found");
                                    return generateApiGatewayProxyErrorResponse(
                                            400, ErrorResponse.ERROR_1018);
                                }
                                attachSessionIdToLogs(session);
                                var clientID =
                                        new ClientID(
                                                configurationService
                                                        .getDocAppAuthorisationClientId());
                                var state = new State();
                                var encryptedJWT =
                                        authorisationService.constructRequestJWT(
                                                state, clientSession.getDocAppSubjectId());
                                var authRequestBuilder =
                                        new AuthorizationRequest.Builder(
                                                        new ResponseType(ResponseType.Value.CODE),
                                                        clientID)
                                                .endpointURI(
                                                        configurationService
                                                                .getDocAppAuthorisationURI())
                                                .requestObject(encryptedJWT);

                                var authorisationRequest = authRequestBuilder.build();
                                authorisationService.storeState(session.getSessionId(), state);
                                LOG.info(
                                        "DocAppAuthorizeHandler successfully processed request, redirect URI {}",
                                        authorisationRequest.toURI().toString());

                                return generateApiGatewayProxyResponse(
                                        200,
                                        new DocAppAuthorisationResponse(
                                                authorisationRequest.toURI().toString()));

                            } catch (JsonProcessingException e) {
                                return generateApiGatewayProxyErrorResponse(
                                        400, ErrorResponse.ERROR_1001);
                            }
                        });
    }
}

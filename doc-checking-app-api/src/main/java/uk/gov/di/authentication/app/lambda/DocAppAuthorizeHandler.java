package uk.gov.di.authentication.app.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.authentication.app.entity.DocAppAuthorisationResponse;
import uk.gov.di.orchestration.audit.TxmaAuditUser;
import uk.gov.di.orchestration.shared.entity.ErrorResponse;
import uk.gov.di.orchestration.shared.serialization.Json.JsonException;
import uk.gov.di.orchestration.shared.services.AuditService;
import uk.gov.di.orchestration.shared.services.ClientService;
import uk.gov.di.orchestration.shared.services.ClientSessionService;
import uk.gov.di.orchestration.shared.services.CloudwatchMetricsService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.DocAppAuthorisationService;
import uk.gov.di.orchestration.shared.services.DynamoClientService;
import uk.gov.di.orchestration.shared.services.JwksService;
import uk.gov.di.orchestration.shared.services.KmsConnectionService;
import uk.gov.di.orchestration.shared.services.NoSessionOrchestrationService;
import uk.gov.di.orchestration.shared.services.RedisConnectionService;
import uk.gov.di.orchestration.shared.services.SessionService;

import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Objects;

import static uk.gov.di.authentication.app.domain.DocAppAuditableEvent.DOC_APP_AUTHORISATION_REQUESTED;
import static uk.gov.di.orchestration.shared.domain.RequestHeaders.CLIENT_SESSION_ID_HEADER;
import static uk.gov.di.orchestration.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.orchestration.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.orchestration.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.orchestration.shared.helpers.IpAddressHelper.extractIpAddress;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.CLIENT_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.CLIENT_SESSION_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.GOVUK_SIGNIN_JOURNEY_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.PERSISTENT_SESSION_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachSessionIdToLogs;
import static uk.gov.di.orchestration.shared.helpers.PersistentIdHelper.extractPersistentIdFromHeaders;
import static uk.gov.di.orchestration.shared.helpers.RequestHeaderHelper.getHeaderValueFromHeaders;

public class DocAppAuthorizeHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(DocAppAuthorizeHandler.class);

    private final SessionService sessionService;
    private final ClientSessionService clientSessionService;
    private final DocAppAuthorisationService authorisationService;
    private final ConfigurationService configurationService;
    private final AuditService auditService;
    private final ClientService clientService;
    private final CloudwatchMetricsService cloudwatchMetricsService;
    private final NoSessionOrchestrationService noSessionOrchestrationService;

    public DocAppAuthorizeHandler() {
        this(ConfigurationService.getInstance());
    }

    public DocAppAuthorizeHandler(ConfigurationService configurationService) {
        var kmsConnectionService = new KmsConnectionService(configurationService);
        this.configurationService = configurationService;
        this.sessionService = new SessionService(configurationService);
        this.clientSessionService = new ClientSessionService(configurationService);
        this.authorisationService =
                new DocAppAuthorisationService(
                        configurationService,
                        new RedisConnectionService(configurationService),
                        kmsConnectionService,
                        new JwksService(configurationService, kmsConnectionService));
        this.auditService = new AuditService(configurationService);
        this.clientService = new DynamoClientService(configurationService);
        this.cloudwatchMetricsService = new CloudwatchMetricsService(configurationService);
        this.noSessionOrchestrationService =
                new NoSessionOrchestrationService(
                        new RedisConnectionService(configurationService),
                        clientSessionService,
                        configurationService);
    }

    public DocAppAuthorizeHandler(
            ConfigurationService configurationService, RedisConnectionService redis) {
        var kmsConnectionService = new KmsConnectionService(configurationService);
        this.configurationService = configurationService;
        this.sessionService = new SessionService(configurationService, redis);
        this.clientSessionService = new ClientSessionService(configurationService, redis);
        this.authorisationService =
                new DocAppAuthorisationService(
                        configurationService,
                        new RedisConnectionService(configurationService),
                        kmsConnectionService,
                        new JwksService(configurationService, kmsConnectionService));
        this.auditService = new AuditService(configurationService);
        this.clientService = new DynamoClientService(configurationService);
        this.cloudwatchMetricsService = new CloudwatchMetricsService(configurationService);
        this.noSessionOrchestrationService =
                new NoSessionOrchestrationService(
                        redis, clientSessionService, configurationService);
    }

    public DocAppAuthorizeHandler(
            SessionService sessionService,
            ClientSessionService clientSessionService,
            DocAppAuthorisationService authorisationService,
            ConfigurationService configurationService,
            AuditService auditService,
            ClientService clientService,
            CloudwatchMetricsService cloudwatchMetricsService,
            NoSessionOrchestrationService noSessionOrchestrationService) {
        this.sessionService = sessionService;
        this.clientSessionService = clientSessionService;
        this.authorisationService = authorisationService;
        this.configurationService = configurationService;
        this.auditService = auditService;
        this.clientService = clientService;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
        this.noSessionOrchestrationService = noSessionOrchestrationService;
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        ThreadContext.clearMap();
        return segmentedFunctionCall(
                "doc-app-api::" + getClass().getSimpleName(),
                () -> docAppAuthoriseRequestHandler(input, context));
    }

    public APIGatewayProxyResponseEvent docAppAuthoriseRequestHandler(
            APIGatewayProxyRequestEvent input, Context context) {
        try {
            LOG.info("DocAppAuthorizeHandler received request");

            var session =
                    sessionService.getSessionFromRequestHeaders(input.getHeaders()).orElse(null);
            if (Objects.isNull(session)) {
                LOG.warn("Session cannot be found");
                return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1000);
            }
            attachSessionIdToLogs(session);
            var clientSession =
                    clientSessionService
                            .getClientSessionFromRequestHeaders(input.getHeaders())
                            .orElse(null);
            if (Objects.isNull(clientSession)) {
                LOG.warn("ClientSession cannot be found");
                return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1018);
            }
            String clientSessionId =
                    getHeaderValueFromHeaders(
                            input.getHeaders(),
                            CLIENT_SESSION_ID_HEADER,
                            configurationService.getHeadersCaseInsensitive());
            attachLogFieldToLogs(CLIENT_SESSION_ID, clientSessionId);
            attachLogFieldToLogs(GOVUK_SIGNIN_JOURNEY_ID, clientSessionId);
            attachLogFieldToLogs(
                    PERSISTENT_SESSION_ID, extractPersistentIdFromHeaders(input.getHeaders()));
            var clientRegistry =
                    clientSession.getAuthRequestParams().get("client_id").stream()
                            .findFirst()
                            .flatMap(clientService::getClient)
                            .orElseThrow();
            attachLogFieldToLogs(CLIENT_ID, clientRegistry.getClientID());
            var state = new State();
            var encryptedJWT =
                    authorisationService.constructRequestJWT(
                            state,
                            clientSession.getDocAppSubjectId(),
                            clientRegistry,
                            clientSessionId);
            var authRequestBuilder =
                    new AuthorizationRequest.Builder(
                                    new ResponseType(ResponseType.Value.CODE),
                                    new ClientID(
                                            configurationService.getDocAppAuthorisationClientId()))
                            .endpointURI(configurationService.getDocAppAuthorisationURI())
                            .requestObject(encryptedJWT);

            var authorisationRequest = authRequestBuilder.build();
            authorisationService.storeState(session.getSessionId(), state);
            noSessionOrchestrationService.storeClientSessionIdAgainstState(clientSessionId, state);

            var user =
                    TxmaAuditUser.user()
                            .withGovukSigninJourneyId(clientSessionId)
                            .withSessionId(session.getSessionId())
                            .withUserId(clientSession.getDocAppSubjectId().getValue())
                            .withIpAddress(extractIpAddress(input))
                            .withPersistentSessionId(
                                    extractPersistentIdFromHeaders(input.getHeaders()));

            auditService.submitAuditEvent(
                    DOC_APP_AUTHORISATION_REQUESTED, clientRegistry.getClientID(), user);
            LOG.info(
                    "DocAppAuthorizeHandler successfully processed request, redirect URI {}",
                    authorisationRequest.toURI().toString());

            cloudwatchMetricsService.incrementCounter(
                    "DocAppHandoff", Map.of("Environment", configurationService.getEnvironment()));
            return generateApiGatewayProxyResponse(
                    200, new DocAppAuthorisationResponse(authorisationRequest.toURI().toString()));

        } catch (JsonException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        } catch (NoSuchElementException e) {
            LOG.warn("Invalid client or client not found in Client Registry");
            return generateApiGatewayProxyResponse(
                    400, OAuth2Error.INVALID_CLIENT.toJSONObject().toJSONString());
        }
    }
}

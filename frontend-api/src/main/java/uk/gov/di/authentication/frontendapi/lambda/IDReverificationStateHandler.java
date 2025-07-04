package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.frontendapi.entity.IDReverificationStateRequest;
import uk.gov.di.authentication.frontendapi.entity.IDReverificationStateResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.IDReverificationStateService;
import uk.gov.di.authentication.shared.services.SerializationService;

import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_REVERIFY_AUTHORISATION_ERROR_RECEIVED;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_JOURNEY_TYPE;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.AWS_REQUEST_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.CLIENT_SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.authentication.shared.helpers.TxmaAuditHelper.getTxmaAuditEncodedHeader;

public class IDReverificationStateHandler {
    private final Json objectMapper = SerializationService.getInstance();
    private final AuditService auditService;
    private final IDReverificationStateService idReverificationStateService;
    private final CloudwatchMetricsService cloudwatchMetricsService;

    public IDReverificationStateHandler(
            AuditService auditService,
            IDReverificationStateService idReverificationStateService,
            CloudwatchMetricsService cloudwatchMetricsService) {
        this.auditService = auditService;
        this.idReverificationStateService = idReverificationStateService;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
    }

    public IDReverificationStateHandler(ConfigurationService configurationService) {
        this(
                new AuditService(configurationService),
                new IDReverificationStateService(configurationService),
                new CloudwatchMetricsService(configurationService));
    }

    public IDReverificationStateHandler() {
        this(ConfigurationService.getInstance());
    }

    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) throws Json.JsonException {
        ThreadContext.clearMap();
        attachLogFieldToLogs(AWS_REQUEST_ID, context.getAwsRequestId());
        var txmaAuditEncoded = getTxmaAuditEncodedHeader(input);
        var auditContext = AuditContext.emptyAuditContext().withTxmaAuditEncoded(txmaAuditEncoded);
        var request = objectMapper.readValue(input.getBody(), IDReverificationStateRequest.class);
        return fetchOrchestrationRedirectUrl(request, auditContext);
    }

    private APIGatewayProxyResponseEvent fetchOrchestrationRedirectUrl(
            IDReverificationStateRequest request, AuditContext baseAuditContext)
            throws Json.JsonException {
        var idReverificationStateMaybe =
                idReverificationStateService.get(request.authenticationState());
        if (idReverificationStateMaybe.isEmpty()) {
            return generateApiGatewayProxyResponse(404, "");
        }
        var idReverificationState = idReverificationStateMaybe.get();
        attachLogFieldToLogs(CLIENT_SESSION_ID, idReverificationState.getClientSessionId());

        var auditContext =
                baseAuditContext.withClientSessionId(idReverificationState.getClientSessionId());
        auditService.submitAuditEvent(
                AUTH_REVERIFY_AUTHORISATION_ERROR_RECEIVED,
                auditContext,
                AuditService.MetadataPair.pair(
                        AUDIT_EVENT_EXTENSIONS_JOURNEY_TYPE,
                        JourneyType.ACCOUNT_RECOVERY.getValue()));
        cloudwatchMetricsService.incrementReverifyAuthorisationErrorCount();
        var response =
                new IDReverificationStateResponse(
                        idReverificationState.getOrchestrationRedirectUrl());
        return generateApiGatewayProxyResponse(200, response);
    }
}

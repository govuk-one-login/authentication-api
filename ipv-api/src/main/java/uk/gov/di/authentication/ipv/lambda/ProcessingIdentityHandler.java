package uk.gov.di.authentication.ipv.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.ipv.domain.IPVAuditableEvent;
import uk.gov.di.authentication.ipv.entity.ProcessingIdentityInterventionResponse;
import uk.gov.di.authentication.ipv.entity.ProcessingIdentityRequest;
import uk.gov.di.authentication.ipv.entity.ProcessingIdentityResponse;
import uk.gov.di.authentication.ipv.entity.ProcessingIdentityStatus;
import uk.gov.di.orchestration.audit.AuditContext;
import uk.gov.di.orchestration.shared.entity.AccountIntervention;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.DestroySessionsRequest;
import uk.gov.di.orchestration.shared.entity.ResponseHeaders;
import uk.gov.di.orchestration.shared.helpers.IpAddressHelper;
import uk.gov.di.orchestration.shared.helpers.PersistentIdHelper;
import uk.gov.di.orchestration.shared.lambda.BaseFrontendHandler;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.services.AccountInterventionService;
import uk.gov.di.orchestration.shared.services.AuditService;
import uk.gov.di.orchestration.shared.services.CloudwatchMetricsService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.DynamoClientService;
import uk.gov.di.orchestration.shared.services.DynamoIdentityService;
import uk.gov.di.orchestration.shared.services.LogoutService;
import uk.gov.di.orchestration.shared.services.OrchClientSessionService;
import uk.gov.di.orchestration.shared.services.OrchSessionService;
import uk.gov.di.orchestration.shared.state.UserContext;

import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Optional;

import static uk.gov.di.authentication.ipv.utils.IdentityProgressUtils.getProcessingIdentityStatus;
import static uk.gov.di.orchestration.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.orchestration.shared.helpers.AuditHelper.attachTxmaAuditFieldFromHeaders;

public class ProcessingIdentityHandler extends BaseFrontendHandler<ProcessingIdentityRequest> {

    private final DynamoIdentityService dynamoIdentityService;
    private final AccountInterventionService accountInterventionService;
    private final AuditService auditService;
    private final CloudwatchMetricsService cloudwatchMetricsService;
    private final LogoutService logoutService;

    private static final Logger LOG = LogManager.getLogger(ProcessingIdentityHandler.class);

    public ProcessingIdentityHandler(ConfigurationService configurationService) {
        super(ProcessingIdentityRequest.class, configurationService);
        this.dynamoIdentityService = new DynamoIdentityService(configurationService);
        this.auditService = new AuditService(configurationService);
        this.cloudwatchMetricsService = new CloudwatchMetricsService();
        this.accountInterventionService =
                new AccountInterventionService(
                        configurationService, cloudwatchMetricsService, auditService);
        this.logoutService = new LogoutService(configurationService);
    }

    public ProcessingIdentityHandler() {
        this(ConfigurationService.getInstance());
    }

    public ProcessingIdentityHandler(
            DynamoIdentityService dynamoIdentityService,
            AccountInterventionService accountInterventionService,
            DynamoClientService dynamoClientService,
            ConfigurationService configurationService,
            AuditService auditService,
            CloudwatchMetricsService cloudwatchMetricsService,
            LogoutService logoutService,
            OrchSessionService orchSessionService,
            OrchClientSessionService orchClientSessionService) {
        super(
                ProcessingIdentityRequest.class,
                configurationService,
                dynamoClientService,
                orchSessionService,
                orchClientSessionService);
        this.dynamoIdentityService = dynamoIdentityService;
        this.accountInterventionService = accountInterventionService;
        this.auditService = auditService;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
        this.logoutService = logoutService;
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
            ProcessingIdentityRequest request,
            UserContext userContext) {
        LOG.info("ProcessingIdentity request received");
        attachTxmaAuditFieldFromHeaders(input.getHeaders());
        try {
            ClientRegistry client = userContext.getClient().orElseThrow();

            int processingAttempts =
                    userContext.getOrchSession().incrementProcessingIdentityAttempts();
            LOG.info(
                    "Attempting to find identity credentials in dynamo. Attempt: {}",
                    processingAttempts);

            var identityCredentials =
                    dynamoIdentityService.getIdentityCredentials(userContext.getClientSessionId());
            var processingStatus =
                    getProcessingIdentityStatus(identityCredentials, processingAttempts);
            if (processingStatus == ProcessingIdentityStatus.NO_ENTRY) {
                userContext.getOrchSession().resetProcessingIdentityAttempts();
            }
            cloudwatchMetricsService.incrementCounter(
                    "ProcessingIdentity",
                    Map.of(
                            "Environment",
                            configurationService.getEnvironment(),
                            "Status",
                            processingStatus.toString()));

            var auditContext =
                    new AuditContext(
                            userContext.getClientSessionId(),
                            userContext.getSessionId(),
                            client.getClientID(),
                            AuditService.UNKNOWN,
                            Optional.ofNullable(request.getEmail()).orElse(AuditService.UNKNOWN),
                            IpAddressHelper.extractIpAddress(input),
                            AuditService.UNKNOWN,
                            PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders()));

            auditService.submitAuditEvent(
                    IPVAuditableEvent.PROCESSING_IDENTITY_REQUEST, auditContext);
            orchSessionService.updateSession(userContext.getOrchSession());
            LOG.info(
                    "Generating ProcessingIdentityResponse with ProcessingIdentityStatus: {}",
                    processingStatus);
            if (processingStatus == ProcessingIdentityStatus.COMPLETED) {
                AccountIntervention intervention =
                        accountInterventionService.getAccountIntervention(
                                userContext.getOrchSession().getInternalCommonSubjectId(),
                                auditContext);
                if (configurationService.isAccountInterventionServiceActionEnabled()
                        && (intervention.getSuspended() || intervention.getBlocked())) {
                    return performIntervention(input, userContext, client, intervention);
                }
            } else if (processingStatus == ProcessingIdentityStatus.ERROR) {
                LOG.error("Error response received from SPOT");
            }
            return generateApiGatewayProxyResponse(
                    200, new ProcessingIdentityResponse(processingStatus));
        } catch (Json.JsonException e) {
            LOG.error("Unable to generate ProcessingIdentityResponse");
            throw new RuntimeException();
        } catch (NoSuchElementException e) {
            LOG.error(
                    "Issue retrieving ClientRegistry from UserContext. ClientRegistry is present: {}",
                    userContext.getClient().isPresent());
            throw new RuntimeException();
        }
    }

    private APIGatewayProxyResponseEvent performIntervention(
            APIGatewayProxyRequestEvent input,
            UserContext userContext,
            ClientRegistry client,
            AccountIntervention intervention)
            throws Json.JsonException {
        var logoutResult =
                logoutService.handleAccountInterventionLogout(
                        new DestroySessionsRequest(
                                userContext.getSessionId(), userContext.getOrchSession()),
                        userContext.getOrchSession().getInternalCommonSubjectId(),
                        input,
                        client.getClientID(),
                        intervention);
        var redirectUrl = logoutResult.getHeaders().get(ResponseHeaders.LOCATION);
        return generateApiGatewayProxyResponse(
                200,
                new ProcessingIdentityInterventionResponse(
                        ProcessingIdentityStatus.INTERVENTION, redirectUrl));
    }
}

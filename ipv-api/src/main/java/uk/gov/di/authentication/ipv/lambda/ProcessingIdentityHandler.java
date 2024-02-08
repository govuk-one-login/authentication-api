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
import uk.gov.di.orchestration.shared.entity.AccountInterventionStatus;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.ResponseHeaders;
import uk.gov.di.orchestration.shared.entity.UserProfile;
import uk.gov.di.orchestration.shared.helpers.ClientSubjectHelper;
import uk.gov.di.orchestration.shared.helpers.IpAddressHelper;
import uk.gov.di.orchestration.shared.helpers.PersistentIdHelper;
import uk.gov.di.orchestration.shared.lambda.BaseFrontendHandler;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.services.AccountInterventionService;
import uk.gov.di.orchestration.shared.services.AuditService;
import uk.gov.di.orchestration.shared.services.ClientSessionService;
import uk.gov.di.orchestration.shared.services.CloudwatchMetricsService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.DynamoClientService;
import uk.gov.di.orchestration.shared.services.DynamoIdentityService;
import uk.gov.di.orchestration.shared.services.DynamoService;
import uk.gov.di.orchestration.shared.services.LogoutService;
import uk.gov.di.orchestration.shared.services.SessionService;
import uk.gov.di.orchestration.shared.state.UserContext;

import java.net.URI;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Objects;

import static uk.gov.di.orchestration.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.orchestration.shared.helpers.InstrumentationHelper.segmentedFunctionCall;

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
            SessionService sessionService,
            ClientSessionService clientSessionService,
            DynamoClientService dynamoClientService,
            DynamoService dynamoService,
            ConfigurationService configurationService,
            AuditService auditService,
            CloudwatchMetricsService cloudwatchMetricsService,
            LogoutService logoutService) {
        super(
                ProcessingIdentityRequest.class,
                configurationService,
                sessionService,
                clientSessionService,
                dynamoClientService,
                dynamoService);
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
        try {
            UserProfile userProfile = userContext.getUserProfile().orElseThrow();
            ClientRegistry client = userContext.getClient().orElseThrow();
            var rpPairwiseSubject =
                    ClientSubjectHelper.getSubject(
                            userProfile,
                            client,
                            authenticationService,
                            configurationService.getInternalSectorUri());
            var internalPairwiseSubjectId =
                    ClientSubjectHelper.calculatePairwiseIdentifier(
                            userProfile.getSubjectID(),
                            URI.create(configurationService.getInternalSectorUri()),
                            authenticationService.getOrGenerateSalt(userProfile));
            int processingAttempts = userContext.getSession().incrementProcessingIdentityAttempts();
            LOG.info(
                    "Attempting to find identity credentials in dynamo. Attempt: {}",
                    processingAttempts);

            var identityCredentials =
                    dynamoIdentityService.getIdentityCredentials(rpPairwiseSubject.getValue());
            var processingStatus = ProcessingIdentityStatus.PROCESSING;
            if (identityCredentials.isEmpty()
                    && userContext.getSession().getProcessingIdentityAttempts() == 1) {
                processingStatus = ProcessingIdentityStatus.NO_ENTRY;
                userContext.getSession().resetProcessingIdentityAttempts();
            } else if (identityCredentials.isEmpty()) {
                processingStatus = ProcessingIdentityStatus.ERROR;
            } else if (Objects.nonNull(identityCredentials.get().getCoreIdentityJWT())) {
                processingStatus = ProcessingIdentityStatus.COMPLETED;
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
                            userContext.getSession().getSessionId(),
                            client.getClientID(),
                            AuditService.UNKNOWN,
                            userContext
                                    .getUserProfile()
                                    .map(UserProfile::getEmail)
                                    .orElse(AuditService.UNKNOWN),
                            IpAddressHelper.extractIpAddress(input),
                            AuditService.UNKNOWN,
                            PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders()));

            auditService.submitAuditEvent(
                    IPVAuditableEvent.PROCESSING_IDENTITY_REQUEST, auditContext);
            sessionService.save(userContext.getSession());
            LOG.info(
                    "Generating ProcessingIdentityResponse with ProcessingIdentityStatus: {}",
                    processingStatus);
            if (processingStatus == ProcessingIdentityStatus.COMPLETED) {
                var aisResult =
                        segmentedFunctionCall(
                                "AIS: getAccountStatus",
                                () ->
                                        accountInterventionService.getAccountStatus(
                                                internalPairwiseSubjectId, auditContext));
                if (configurationService.isAccountInterventionServiceActionEnabled()
                        && (aisResult.suspended() || aisResult.blocked())) {
                    return performIntervention(input, userContext, client, aisResult);
                }
            }
            return generateApiGatewayProxyResponse(
                    200, new ProcessingIdentityResponse(processingStatus));
        } catch (Json.JsonException e) {
            LOG.error("Unable to generate ProcessingIdentityResponse");
            throw new RuntimeException();
        } catch (NoSuchElementException e) {
            LOG.warn(
                    "Issue retrieving UserProfile or ClientRegistry from UserContext. UserProfile is present: {}, ClientRegistry is present: {}",
                    userContext.getUserProfile().isPresent(),
                    userContext.getClient().isPresent());
            throw new RuntimeException();
        }
    }

    private APIGatewayProxyResponseEvent performIntervention(
            APIGatewayProxyRequestEvent input,
            UserContext userContext,
            ClientRegistry client,
            AccountInterventionStatus aisResult)
            throws Json.JsonException {
        var logoutResult =
                logoutService.handleAccountInterventionLogout(
                        userContext.getSession(), input, client.getClientID(), aisResult);
        var redirectUrl = logoutResult.getHeaders().get(ResponseHeaders.LOCATION);
        return generateApiGatewayProxyResponse(
                200,
                new ProcessingIdentityInterventionResponse(
                        ProcessingIdentityStatus.INTERVENTION, redirectUrl));
    }
}

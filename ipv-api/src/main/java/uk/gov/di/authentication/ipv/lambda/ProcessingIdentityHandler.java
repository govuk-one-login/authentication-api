package uk.gov.di.authentication.ipv.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.ipv.domain.IPVAuditableEvent;
import uk.gov.di.authentication.ipv.entity.ProcessingIdentityRequest;
import uk.gov.di.authentication.ipv.entity.ProcessingIdentityResponse;
import uk.gov.di.authentication.ipv.entity.ProcessingIdentityStatus;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.lambda.BaseFrontendHandler;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoClientService;
import uk.gov.di.authentication.shared.services.DynamoIdentityService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.NoSuchElementException;
import java.util.Objects;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;

public class ProcessingIdentityHandler extends BaseFrontendHandler<ProcessingIdentityRequest> {

    private final DynamoIdentityService dynamoIdentityService;
    private final AuditService auditService;

    private static final Logger LOG = LogManager.getLogger(ProcessingIdentityHandler.class);

    public ProcessingIdentityHandler(ConfigurationService configurationService) {
        super(ProcessingIdentityRequest.class, configurationService);
        this.dynamoIdentityService = new DynamoIdentityService(configurationService);
        this.auditService = new AuditService(configurationService);
    }

    public ProcessingIdentityHandler() {
        this(ConfigurationService.getInstance());
    }

    public ProcessingIdentityHandler(
            DynamoIdentityService dynamoIdentityService,
            SessionService sessionService,
            ClientSessionService clientSessionService,
            DynamoClientService dynamoClientService,
            DynamoService dynamoService,
            ConfigurationService configurationService,
            AuditService auditService) {
        super(
                ProcessingIdentityRequest.class,
                configurationService,
                sessionService,
                clientSessionService,
                dynamoClientService,
                dynamoService);
        this.dynamoIdentityService = dynamoIdentityService;
        this.auditService = auditService;
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequestWithUserContext(
            APIGatewayProxyRequestEvent input,
            Context context,
            ProcessingIdentityRequest request,
            UserContext userContext) {
        LOG.info("ProcessingIdentity request received");
        try {
            var pairwiseSubject =
                    ClientSubjectHelper.getSubject(
                            userContext.getUserProfile().orElseThrow(),
                            userContext.getClient().orElseThrow(),
                            authenticationService);
            int processingAttempts = userContext.getSession().incrementProcessingIdentityAttempts();
            LOG.info(
                    "Attempting to find identity credentials in dynamo. Attempt: {}",
                    processingAttempts);

            var identityCredentials =
                    dynamoIdentityService.getIdentityCredentials(pairwiseSubject.getValue());
            var processingStatus = ProcessingIdentityStatus.PROCESSING;
            if (identityCredentials.isEmpty()
                    && userContext.getSession().getProcessingIdentityAttempts() == 1) {
                processingStatus = ProcessingIdentityStatus.NO_ENTRY;
            } else if (identityCredentials.isEmpty()) {
                processingStatus = ProcessingIdentityStatus.ERROR;
            } else if (Objects.nonNull(identityCredentials.get().getCoreIdentityJWT())) {
                processingStatus = ProcessingIdentityStatus.COMPLETED;
            }
            auditService.submitAuditEvent(
                    IPVAuditableEvent.PROCESSING_IDENTITY_REQUEST,
                    context.getAwsRequestId(),
                    userContext.getSession().getSessionId(),
                    userContext.getClient().get().getClientID(),
                    AuditService.UNKNOWN,
                    userContext
                            .getUserProfile()
                            .map(UserProfile::getEmail)
                            .orElse(AuditService.UNKNOWN),
                    IpAddressHelper.extractIpAddress(input),
                    PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders()),
                    AuditService.UNKNOWN);
            sessionService.save(userContext.getSession());
            LOG.info(
                    "Generating ProcessingIdentityResponse with ProcessingIdentityStatus: {}",
                    processingStatus);
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
}

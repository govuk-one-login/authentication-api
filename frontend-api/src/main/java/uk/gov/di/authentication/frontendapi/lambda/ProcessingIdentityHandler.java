package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.frontendapi.entity.ProcessingIdentityRequest;
import uk.gov.di.authentication.frontendapi.entity.ProcessingIdentityResponse;
import uk.gov.di.authentication.frontendapi.entity.ProcessingIdentityStatus;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.lambda.BaseFrontendHandler;
import uk.gov.di.authentication.shared.serialization.Json;
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

    private static final Logger LOG = LogManager.getLogger(ProcessingIdentityHandler.class);

    public ProcessingIdentityHandler(ConfigurationService configurationService) {
        super(ProcessingIdentityRequest.class, configurationService);
        this.dynamoIdentityService = new DynamoIdentityService(configurationService);
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
            ConfigurationService configurationService) {
        super(
                ProcessingIdentityRequest.class,
                configurationService,
                sessionService,
                clientSessionService,
                dynamoClientService,
                dynamoService);
        this.dynamoIdentityService = dynamoIdentityService;
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
            LOG.info("Attempting to find identity credentials in dynamo");
            var identityCredentials =
                    dynamoIdentityService.getIdentityCredentials(pairwiseSubject.getValue());
            var processingStatus = ProcessingIdentityStatus.PROCESSING;
            if (identityCredentials.isEmpty()) {
                processingStatus = ProcessingIdentityStatus.ERROR;
            } else if (Objects.nonNull(identityCredentials.get().getCoreIdentityJWT())) {
                processingStatus = ProcessingIdentityStatus.COMPLETED;
            }
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

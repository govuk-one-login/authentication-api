package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent;
import uk.gov.di.accountmanagement.entity.NotificationType;
import uk.gov.di.accountmanagement.entity.NotifyRequest;
import uk.gov.di.accountmanagement.entity.UpdatePasswordRequest;
import uk.gov.di.accountmanagement.services.AwsSqsClient;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.Argon2MatcherHelper;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.helpers.RequestBodyHelper;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;

import java.util.Map;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateEmptySuccessApiGatewayResponse;
import static uk.gov.di.authentication.shared.helpers.WarmerHelper.isWarming;

public class UpdatePasswordHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final DynamoService dynamoService;
    private final AwsSqsClient sqsClient;
    private final AuditService auditService;

    private static final Logger LOGGER = LogManager.getLogger(UpdatePasswordHandler.class);

    public UpdatePasswordHandler() {
        ConfigurationService configurationService = ConfigurationService.getInstance();
        this.dynamoService = new DynamoService(ConfigurationService.getInstance());
        this.sqsClient =
                new AwsSqsClient(
                        configurationService.getAwsRegion(),
                        configurationService.getEmailQueueUri(),
                        configurationService.getSqsEndpointUri());
        this.auditService = new AuditService(configurationService);
    }

    public UpdatePasswordHandler(
            DynamoService dynamoService, AwsSqsClient sqsClient, AuditService auditService) {
        this.dynamoService = dynamoService;
        this.sqsClient = sqsClient;
        this.auditService = auditService;
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return isWarming(input)
                .orElseGet(
                        () -> {
                            LOGGER.info("UpdatePasswordHandler received request");
                            context.getClientContext();
                            try {
                                UpdatePasswordRequest updatePasswordRequest =
                                        objectMapper.readValue(
                                                input.getBody(), UpdatePasswordRequest.class);

                                UserProfile userProfile =
                                        dynamoService.getUserProfileByEmail(
                                                updatePasswordRequest.getEmail());
                                Map<String, Object> authorizerParams =
                                        input.getRequestContext().getAuthorizer();

                                RequestBodyHelper.validatePrincipal(
                                        new Subject(userProfile.getPublicSubjectID()),
                                        authorizerParams);

                                String currentPassword =
                                        dynamoService
                                                .getUserCredentialsFromEmail(
                                                        updatePasswordRequest.getEmail())
                                                .getPassword();

                                if (verifyPassword(
                                        currentPassword, updatePasswordRequest.getNewPassword())) {
                                    LOGGER.info("New password is the same as the old password");
                                    return generateApiGatewayProxyErrorResponse(
                                            400, ErrorResponse.ERROR_1024);
                                }

                                dynamoService.updatePassword(
                                        updatePasswordRequest.getEmail(),
                                        updatePasswordRequest.getNewPassword());

                                LOGGER.info(
                                        "User Password has successfully been updated.  Adding confirmation message to SQS queue");
                                NotifyRequest notifyRequest =
                                        new NotifyRequest(
                                                updatePasswordRequest.getEmail(),
                                                NotificationType.PASSWORD_UPDATED);
                                sqsClient.send(objectMapper.writeValueAsString((notifyRequest)));
                                LOGGER.info(
                                        "Message successfully added to queue. Generating successful gateway response");

                                auditService.submitAuditEvent(
                                        AccountManagementAuditableEvent.UPDATE_PASSWORD,
                                        context.getAwsRequestId(),
                                        AuditService.UNKNOWN,
                                        AuditService.UNKNOWN,
                                        userProfile.getSubjectID(),
                                        userProfile.getEmail(),
                                        IpAddressHelper.extractIpAddress(input),
                                        userProfile.getPhoneNumber(),
                                        PersistentIdHelper.extractPersistentIdFromHeaders(
                                                input.getHeaders()));

                                return generateEmptySuccessApiGatewayResponse();

                            } catch (JsonProcessingException | IllegalArgumentException e) {
                                LOGGER.error(
                                        "UpdatePassword request is missing or contains invalid parameters.");
                                return generateApiGatewayProxyErrorResponse(
                                        400, ErrorResponse.ERROR_1001);
                            }
                        });
    }

    private static boolean verifyPassword(String hashedPassword, String password) {
        return Argon2MatcherHelper.matchRawStringWithEncoded(password, hashedPassword);
    }
}

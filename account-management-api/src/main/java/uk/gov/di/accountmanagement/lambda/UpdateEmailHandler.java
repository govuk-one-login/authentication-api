package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent;
import uk.gov.di.accountmanagement.entity.NotificationType;
import uk.gov.di.accountmanagement.entity.NotifyRequest;
import uk.gov.di.accountmanagement.entity.UpdateEmailRequest;
import uk.gov.di.accountmanagement.services.AwsSqsClient;
import uk.gov.di.accountmanagement.services.CodeStorageService;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.RequestBodyHelper;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.ValidationService;

import java.util.Map;
import java.util.Optional;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateEmptySuccessApiGatewayResponse;
import static uk.gov.di.authentication.shared.helpers.WarmerHelper.isWarming;

public class UpdateEmailHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final DynamoService dynamoService;
    private final AwsSqsClient sqsClient;
    private final ValidationService validationService;
    private final CodeStorageService codeStorageService;
    private static final Logger LOGGER = LoggerFactory.getLogger(UpdateEmailHandler.class);
    private final AuditService auditService;

    public UpdateEmailHandler() {
        ConfigurationService configurationService = ConfigurationService.getInstance();
        this.dynamoService = new DynamoService(configurationService);
        this.sqsClient =
                new AwsSqsClient(
                        configurationService.getAwsRegion(),
                        configurationService.getEmailQueueUri(),
                        configurationService.getSqsEndpointUri());
        this.validationService = new ValidationService();
        this.codeStorageService =
                new CodeStorageService(new RedisConnectionService(configurationService));
        this.auditService = new AuditService();
    }

    public UpdateEmailHandler(
            DynamoService dynamoService,
            AwsSqsClient sqsClient,
            ValidationService validationService,
            CodeStorageService codeStorageService,
            AuditService auditService) {
        this.dynamoService = dynamoService;
        this.sqsClient = sqsClient;
        this.validationService = validationService;
        this.codeStorageService = codeStorageService;
        this.auditService = auditService;
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return isWarming(input)
                .orElseGet(
                        () -> {
                            LOGGER.info("UpdateEmailHandler received request");
                            LOGGER.info(
                                    "Authorizer parameters received: {}",
                                    input.getRequestContext().getAuthorizer());
                            try {
                                UpdateEmailRequest updateInfoRequest =
                                        objectMapper.readValue(
                                                input.getBody(), UpdateEmailRequest.class);
                                boolean isValidOtpCode =
                                        codeStorageService.isValidOtpCode(
                                                updateInfoRequest.getReplacementEmailAddress(),
                                                updateInfoRequest.getOtp(),
                                                NotificationType.VERIFY_EMAIL);
                                if (!isValidOtpCode) {
                                    LOGGER.info("Invalid OTP code sent in request");
                                    return generateApiGatewayProxyErrorResponse(
                                            400, ErrorResponse.ERROR_1020);
                                }
                                Optional<ErrorResponse> emailValidationErrors =
                                        validationService.validateEmailAddressUpdate(
                                                updateInfoRequest.getExistingEmailAddress(),
                                                updateInfoRequest.getReplacementEmailAddress());
                                if (emailValidationErrors.isPresent()) {
                                    LOGGER.info(
                                            "Invalid email address with error: {}",
                                            emailValidationErrors.get().getMessage());
                                    return generateApiGatewayProxyErrorResponse(
                                            400, emailValidationErrors.get());
                                }
                                if (dynamoService.userExists(
                                        updateInfoRequest.getReplacementEmailAddress())) {
                                    LOGGER.info(
                                            "An account with this email address already exists");
                                    return generateApiGatewayProxyErrorResponse(
                                            400, ErrorResponse.ERROR_1009);
                                }
                                UserProfile userProfile =
                                        dynamoService.getUserProfileByEmail(
                                                updateInfoRequest.getExistingEmailAddress());
                                Map<String, Object> authorizerParams =
                                        input.getRequestContext().getAuthorizer();
                                RequestBodyHelper.validatePrincipal(
                                        new Subject(userProfile.getPublicSubjectID()),
                                        authorizerParams);
                                dynamoService.updateEmail(
                                        updateInfoRequest.getExistingEmailAddress(),
                                        updateInfoRequest.getReplacementEmailAddress());
                                LOGGER.info(
                                        "Email has successfully been updated. Adding message to SQS queue");
                                NotifyRequest notifyRequest =
                                        new NotifyRequest(
                                                updateInfoRequest.getReplacementEmailAddress(),
                                                NotificationType.EMAIL_UPDATED);
                                sqsClient.send(objectMapper.writeValueAsString((notifyRequest)));

                                auditService.submitAuditEvent(
                                        AccountManagementAuditableEvent.UPDATE_EMAIL,
                                        context.getAwsRequestId(),
                                        AuditService.UNKNOWN,
                                        AuditService.UNKNOWN,
                                        userProfile.getSubjectID(),
                                        userProfile.getEmail(),
                                        IpAddressHelper.extractIpAddress(input),
                                        userProfile.getPhoneNumber());

                                LOGGER.info(
                                        "Message successfully added to queue. Generating successful gateway response");
                                return generateEmptySuccessApiGatewayResponse();
                            } catch (JsonProcessingException | IllegalArgumentException e) {
                                LOGGER.error(
                                        "UpdateInfo request is missing or contains invalid parameters.");
                                return generateApiGatewayProxyErrorResponse(
                                        400, ErrorResponse.ERROR_1001);
                            }
                        });
    }
}

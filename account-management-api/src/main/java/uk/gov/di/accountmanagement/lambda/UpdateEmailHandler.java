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
import uk.gov.di.accountmanagement.entity.UpdateEmailRequest;
import uk.gov.di.accountmanagement.services.AwsSqsClient;
import uk.gov.di.accountmanagement.services.CodeStorageService;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.ObjectMapperFactory;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.helpers.RequestBodyHelper;
import uk.gov.di.authentication.shared.helpers.RequestHeaderHelper;
import uk.gov.di.authentication.shared.helpers.ValidationHelper;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;

import java.util.Map;
import java.util.Optional;

import static uk.gov.di.authentication.shared.domain.RequestHeaders.SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateEmptySuccessApiGatewayResponse;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachSessionIdToLogs;
import static uk.gov.di.authentication.shared.helpers.WarmerHelper.isWarming;

public class UpdateEmailHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final ObjectMapper objectMapper = ObjectMapperFactory.getInstance();
    private final DynamoService dynamoService;
    private final AwsSqsClient sqsClient;
    private final CodeStorageService codeStorageService;
    private static final Logger LOG = LogManager.getLogger(UpdateEmailHandler.class);
    private final AuditService auditService;

    public UpdateEmailHandler() {
        this(ConfigurationService.getInstance());
    }

    public UpdateEmailHandler(
            DynamoService dynamoService,
            AwsSqsClient sqsClient,
            CodeStorageService codeStorageService,
            AuditService auditService) {
        this.dynamoService = dynamoService;
        this.sqsClient = sqsClient;
        this.codeStorageService = codeStorageService;
        this.auditService = auditService;
    }

    public UpdateEmailHandler(ConfigurationService configurationService) {
        this.dynamoService = new DynamoService(configurationService);
        this.sqsClient =
                new AwsSqsClient(
                        configurationService.getAwsRegion(),
                        configurationService.getEmailQueueUri(),
                        configurationService.getSqsEndpointUri());
        this.codeStorageService =
                new CodeStorageService(new RedisConnectionService(configurationService));
        this.auditService = new AuditService(configurationService);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return segmentedFunctionCall("account-management-api::" + getClass().getSimpleName(), () -> updateEmailRequestHandler(input, context));
    }

    public APIGatewayProxyResponseEvent updateEmailRequestHandler(
            APIGatewayProxyRequestEvent input, Context context) {
        return isWarming(input)
                .orElseGet(
                        () -> {
                            String sessionId =
                                    RequestHeaderHelper.getHeaderValueOrElse(
                                            input.getHeaders(), SESSION_ID_HEADER, "");
                            attachSessionIdToLogs(sessionId);
                            LOG.info("UpdateEmailHandler received request");
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
                                    return generateApiGatewayProxyErrorResponse(
                                            400, ErrorResponse.ERROR_1020);
                                }
                                Optional<ErrorResponse> emailValidationErrors =
                                        ValidationHelper.validateEmailAddressUpdate(
                                                updateInfoRequest.getExistingEmailAddress(),
                                                updateInfoRequest.getReplacementEmailAddress());
                                if (emailValidationErrors.isPresent()) {
                                    return generateApiGatewayProxyErrorResponse(
                                            400, emailValidationErrors.get());
                                }
                                if (dynamoService.userExists(
                                        updateInfoRequest.getReplacementEmailAddress())) {
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
                                LOG.info(
                                        "Email has successfully been updated. Adding message to SQS queue");
                                NotifyRequest notifyRequest =
                                        new NotifyRequest(
                                                updateInfoRequest.getReplacementEmailAddress(),
                                                NotificationType.EMAIL_UPDATED);
                                sqsClient.send(objectMapper.writeValueAsString((notifyRequest)));

                                auditService.submitAuditEvent(
                                        AccountManagementAuditableEvent.UPDATE_EMAIL,
                                        context.getAwsRequestId(),
                                        sessionId,
                                        AuditService.UNKNOWN,
                                        userProfile.getSubjectID(),
                                        updateInfoRequest.getReplacementEmailAddress(),
                                        IpAddressHelper.extractIpAddress(input),
                                        userProfile.getPhoneNumber(),
                                        PersistentIdHelper.extractPersistentIdFromHeaders(
                                                input.getHeaders()));

                                LOG.info(
                                        "Message successfully added to queue. Generating successful gateway response");
                                return generateEmptySuccessApiGatewayResponse();
                            } catch (JsonProcessingException | IllegalArgumentException e) {
                                return generateApiGatewayProxyErrorResponse(
                                        400, ErrorResponse.ERROR_1001);
                            }
                        });
    }
}

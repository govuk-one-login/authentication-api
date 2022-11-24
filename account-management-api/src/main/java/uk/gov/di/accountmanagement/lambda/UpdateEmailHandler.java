package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
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
import uk.gov.di.authentication.shared.exceptions.UserNotFoundException;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.LocaleHelper.SupportedLanguage;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.helpers.RequestBodyHelper;
import uk.gov.di.authentication.shared.helpers.RequestHeaderHelper;
import uk.gov.di.authentication.shared.helpers.ValidationHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.serialization.Json.JsonException;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.SerializationService;

import java.util.Map;
import java.util.Optional;

import static uk.gov.di.authentication.shared.domain.RequestHeaders.SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateEmptySuccessApiGatewayResponse;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.authentication.shared.helpers.LocaleHelper.getUserLanguageFromRequestHeaders;
import static uk.gov.di.authentication.shared.helpers.LocaleHelper.matchSupportedLanguage;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachSessionIdToLogs;

public class UpdateEmailHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final Json objectMapper = SerializationService.getInstance();
    private final DynamoService dynamoService;
    private final AwsSqsClient sqsClient;
    private final CodeStorageService codeStorageService;
    private static final Logger LOG = LogManager.getLogger(UpdateEmailHandler.class);
    private final AuditService auditService;
    private final ConfigurationService configurationService;

    public UpdateEmailHandler() {
        this(ConfigurationService.getInstance());
    }

    public UpdateEmailHandler(
            DynamoService dynamoService,
            AwsSqsClient sqsClient,
            CodeStorageService codeStorageService,
            AuditService auditService,
            ConfigurationService configurationService) {
        this.dynamoService = dynamoService;
        this.sqsClient = sqsClient;
        this.codeStorageService = codeStorageService;
        this.auditService = auditService;
        this.configurationService = configurationService;
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
        this.configurationService = configurationService;
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return segmentedFunctionCall(
                "account-management-api::" + getClass().getSimpleName(),
                () -> updateEmailRequestHandler(input, context));
    }

    public APIGatewayProxyResponseEvent updateEmailRequestHandler(
            APIGatewayProxyRequestEvent input, Context context) {
        String sessionId =
                RequestHeaderHelper.getHeaderValueOrElse(input.getHeaders(), SESSION_ID_HEADER, "");
        attachSessionIdToLogs(sessionId);
        LOG.info("UpdateEmailHandler received request");
        SupportedLanguage userLanguage =
                matchSupportedLanguage(
                        getUserLanguageFromRequestHeaders(
                                input.getHeaders(), configurationService));
        try {
            UpdateEmailRequest updateInfoRequest =
                    objectMapper.readValue(input.getBody(), UpdateEmailRequest.class);
            boolean isValidOtpCode =
                    codeStorageService.isValidOtpCode(
                            updateInfoRequest.getReplacementEmailAddress(),
                            updateInfoRequest.getOtp(),
                            NotificationType.VERIFY_EMAIL);
            if (!isValidOtpCode) {
                return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1020);
            }
            Optional<ErrorResponse> emailValidationErrors =
                    ValidationHelper.validateEmailAddressUpdate(
                            updateInfoRequest.getExistingEmailAddress(),
                            updateInfoRequest.getReplacementEmailAddress());
            if (emailValidationErrors.isPresent()) {
                return generateApiGatewayProxyErrorResponse(400, emailValidationErrors.get());
            }
            if (dynamoService.userExists(updateInfoRequest.getReplacementEmailAddress())) {
                return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1009);
            }
            var userProfile =
                    dynamoService
                            .getUserProfileByEmailMaybe(updateInfoRequest.getExistingEmailAddress())
                            .orElseThrow(
                                    () ->
                                            new UserNotFoundException(
                                                    "User not found with given email"));

            Map<String, Object> authorizerParams = input.getRequestContext().getAuthorizer();
            RequestBodyHelper.validatePrincipal(
                    new Subject(userProfile.getPublicSubjectID()), authorizerParams);
            dynamoService.updateEmail(
                    updateInfoRequest.getExistingEmailAddress(),
                    updateInfoRequest.getReplacementEmailAddress());
            LOG.info("Email has successfully been updated. Adding message to SQS queue");
            NotifyRequest notifyRequest =
                    new NotifyRequest(
                            updateInfoRequest.getReplacementEmailAddress(),
                            NotificationType.EMAIL_UPDATED,
                            userLanguage);
            sqsClient.send(objectMapper.writeValueAsString((notifyRequest)));

            auditService.submitAuditEvent(
                    AccountManagementAuditableEvent.UPDATE_EMAIL,
                    AuditService.UNKNOWN,
                    sessionId,
                    AuditService.UNKNOWN,
                    userProfile.getSubjectID(),
                    updateInfoRequest.getReplacementEmailAddress(),
                    IpAddressHelper.extractIpAddress(input),
                    userProfile.getPhoneNumber(),
                    PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders()));

            LOG.info("Message successfully added to queue. Generating successful gateway response");
            return generateEmptySuccessApiGatewayResponse();
        } catch (UserNotFoundException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1010);
        } catch (JsonException | IllegalArgumentException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        }
    }
}

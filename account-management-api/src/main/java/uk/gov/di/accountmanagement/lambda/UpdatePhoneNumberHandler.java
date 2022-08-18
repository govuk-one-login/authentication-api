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
import uk.gov.di.accountmanagement.entity.UpdatePhoneNumberRequest;
import uk.gov.di.accountmanagement.services.AwsSqsClient;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.MFAMethodType;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.helpers.RequestBodyHelper;
import uk.gov.di.authentication.shared.helpers.RequestHeaderHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.serialization.Json.JsonException;
import uk.gov.di.authentication.shared.services.*;
import uk.gov.di.authentication.shared.validation.MfaCodeValidatorFactory;

import java.util.Map;

import static uk.gov.di.authentication.shared.domain.RequestHeaders.SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateEmptySuccessApiGatewayResponse;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachSessionIdToLogs;
import static uk.gov.di.authentication.shared.helpers.WarmerHelper.isWarming;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_BLOCKED_KEY_PREFIX;

public class UpdatePhoneNumberHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final Json objectMapper = SerializationService.getInstance();
    private final DynamoService dynamoService;
    private final AwsSqsClient sqsClient;
    private final CodeStorageService codeStorageService;
    private static final Logger LOG = LogManager.getLogger(UpdatePhoneNumberHandler.class);
    private final AuditService auditService;
    private MfaCodeValidatorFactory mfaCodeValidatorFactory;

    public UpdatePhoneNumberHandler() {
        this(ConfigurationService.getInstance());
    }

    public UpdatePhoneNumberHandler(
            DynamoService dynamoService,
            AwsSqsClient sqsClient,
            CodeStorageService codeStorageService,
            AuditService auditService,
            MfaCodeValidatorFactory mfaCodeValidatorFactory) {
        this.dynamoService = dynamoService;
        this.sqsClient = sqsClient;
        this.codeStorageService = codeStorageService;
        this.auditService = auditService;
        this.mfaCodeValidatorFactory = mfaCodeValidatorFactory;
    }

    public UpdatePhoneNumberHandler(ConfigurationService configurationService) {
        this.dynamoService = new DynamoService(configurationService);
        this.sqsClient =
                new AwsSqsClient(
                        configurationService.getAwsRegion(),
                        configurationService.getEmailQueueUri(),
                        configurationService.getSqsEndpointUri());
        this.codeStorageService =
                new CodeStorageService(new RedisConnectionService(configurationService));
        this.auditService = new AuditService(configurationService);
        this.mfaCodeValidatorFactory =
                new MfaCodeValidatorFactory(configurationService, codeStorageService, dynamoService);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return segmentedFunctionCall(
                "account-management-api::" + getClass().getSimpleName(),
                () -> updatePhoneNumberRequestHandler(input, context));
    }

    public APIGatewayProxyResponseEvent updatePhoneNumberRequestHandler(
            APIGatewayProxyRequestEvent input, Context context) {
        return isWarming(input)
                .orElseGet(
                        () -> {
                            String sessionId =
                                    RequestHeaderHelper.getHeaderValueOrElse(
                                            input.getHeaders(), SESSION_ID_HEADER, "");
                            attachSessionIdToLogs(sessionId);
                            LOG.info("UpdatePhoneNumberHandler received request");
                            try {
                                UpdatePhoneNumberRequest updatePhoneNumberRequest =
                                        objectMapper.readValue(
                                                input.getBody(), UpdatePhoneNumberRequest.class);

                                var validator = mfaCodeValidatorFactory
                                        .getMfaCodeValidator(MFAMethodType.SMS, false, updatePhoneNumberRequest.getEmail());

                                if (validator.isEmpty()) {
                                    return generateApiGatewayProxyErrorResponse(
                                            400, ErrorResponse.ERROR_1002);
                                }

                                var errorResponse =
                                        validator.get().validateCode(
                                                updatePhoneNumberRequest.getOtp());

                                if (ErrorResponse.ERROR_1027.equals(errorResponse.orElse(null))) {
                                    blockCodeForSessionAndResetCount(updatePhoneNumberRequest.getEmail());
                                    return generateApiGatewayProxyErrorResponse(
                                            400, ErrorResponse.ERROR_1027);
                                }

                                if (ErrorResponse.ERROR_1035.equals(errorResponse.orElse(null))) {
                                    return generateApiGatewayProxyErrorResponse(
                                            400, ErrorResponse.ERROR_1035);
                                }

                                UserProfile userProfile =
                                        dynamoService.getUserProfileByEmail(
                                                updatePhoneNumberRequest.getEmail());
                                Map<String, Object> authorizerParams =
                                        input.getRequestContext().getAuthorizer();
                                RequestBodyHelper.validatePrincipal(
                                        new Subject(userProfile.getPublicSubjectID()),
                                        authorizerParams);
                                dynamoService.updatePhoneNumber(
                                        updatePhoneNumberRequest.getEmail(),
                                        updatePhoneNumberRequest.getPhoneNumber());
                                LOG.info(
                                        "Phone Number has successfully been updated. Adding message to SQS queue");
                                NotifyRequest notifyRequest =
                                        new NotifyRequest(
                                                updatePhoneNumberRequest.getEmail(),
                                                NotificationType.PHONE_NUMBER_UPDATED);
                                sqsClient.send(objectMapper.writeValueAsString((notifyRequest)));

                                auditService.submitAuditEvent(
                                        AccountManagementAuditableEvent.UPDATE_PHONE_NUMBER,
                                        context.getAwsRequestId(),
                                        sessionId,
                                        AuditService.UNKNOWN,
                                        userProfile.getSubjectID(),
                                        userProfile.getEmail(),
                                        IpAddressHelper.extractIpAddress(input),
                                        updatePhoneNumberRequest.getPhoneNumber(),
                                        PersistentIdHelper.extractPersistentIdFromHeaders(
                                                input.getHeaders()));

                                LOG.info(
                                        "Message successfully added to queue. Generating successful gateway response");
                                return generateEmptySuccessApiGatewayResponse();
                            } catch (JsonException | IllegalArgumentException e) {
                                return generateApiGatewayProxyErrorResponse(
                                        400, ErrorResponse.ERROR_1001);
                            }
                        });
    }

    private void blockCodeForSessionAndResetCount(String email) {
        codeStorageService.saveBlockedForEmail(
                email,
                CODE_BLOCKED_KEY_PREFIX,
                ConfigurationService.getInstance().getBlockedEmailDuration());
        codeStorageService.deleteIncorrectMfaCodeAttemptsCount(email);
    }
}

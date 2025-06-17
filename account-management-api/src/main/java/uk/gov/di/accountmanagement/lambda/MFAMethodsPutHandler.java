package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.accountmanagement.entity.NotificationType;
import uk.gov.di.accountmanagement.entity.NotifyRequest;
import uk.gov.di.accountmanagement.helpers.PrincipalValidationHelper;
import uk.gov.di.accountmanagement.services.AwsSqsClient;
import uk.gov.di.accountmanagement.services.CodeStorageService;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodNotificationIdentifier;
import uk.gov.di.authentication.shared.entity.mfa.request.MfaMethodUpdateRequest;
import uk.gov.di.authentication.shared.entity.mfa.request.RequestSmsMfaDetail;
import uk.gov.di.authentication.shared.helpers.LocaleHelper;
import uk.gov.di.authentication.shared.helpers.RequestHeaderHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.shared.services.mfa.MFAMethodsService;
import uk.gov.di.authentication.shared.services.mfa.MfaUpdateFailureReason;

import java.util.Map;

import static uk.gov.di.accountmanagement.helpers.MfaMethodResponseConverterHelper.convertMfaMethodsToMfaMethodResponse;
import static uk.gov.di.accountmanagement.helpers.MfaMethodsMigrationHelper.migrateMfaCredentialsForUserIfRequired;
import static uk.gov.di.authentication.shared.domain.RequestHeaders.SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateEmptySuccessApiGatewayResponse;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.authentication.shared.helpers.LocaleHelper.getUserLanguageFromRequestHeaders;
import static uk.gov.di.authentication.shared.helpers.LocaleHelper.matchSupportedLanguage;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachSessionIdToLogs;

public class MFAMethodsPutHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final Json objectMapper = SerializationService.getInstance();

    private static final Logger LOG = LogManager.getLogger(MFAMethodsPutHandler.class);
    private final ConfigurationService configurationService;
    private final CodeStorageService codeStorageService;
    private final MFAMethodsService mfaMethodsService;
    private final AuthenticationService authenticationService;
    private final AwsSqsClient sqsClient;

    private final Json serialisationService = SerializationService.getInstance();

    public MFAMethodsPutHandler() {
        this(ConfigurationService.getInstance());
    }

    public MFAMethodsPutHandler(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.mfaMethodsService = new MFAMethodsService(configurationService);
        this.authenticationService = new DynamoService(configurationService);
        this.codeStorageService =
                new CodeStorageService(new RedisConnectionService(configurationService));
        this.sqsClient =
                new AwsSqsClient(
                        configurationService.getAwsRegion(),
                        configurationService.getEmailQueueUri(),
                        configurationService.getSqsEndpointUri());
    }

    public MFAMethodsPutHandler(
            ConfigurationService configurationService,
            MFAMethodsService mfaMethodsService,
            AuthenticationService authenticationService,
            CodeStorageService codeStorageService,
            AwsSqsClient sqsClient) {
        this.configurationService = configurationService;
        this.mfaMethodsService = mfaMethodsService;
        this.authenticationService = authenticationService;
        this.codeStorageService = codeStorageService;
        this.sqsClient = sqsClient;
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        ThreadContext.clearMap();
        return segmentedFunctionCall(
                "account-management-api::" + getClass().getSimpleName(),
                () -> updateMFAMethodsHandler(input, context));
    }

    public APIGatewayProxyResponseEvent updateMFAMethodsHandler(
            APIGatewayProxyRequestEvent input, Context context) throws Json.JsonException {

        addSessionIdToLogs(input);

        if (!configurationService.isMfaMethodManagementApiEnabled()) {
            LOG.error(
                    "Request to update MFA method in {} environment but feature is switched off.",
                    configurationService.getEnvironment());
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1063);
        }

        var validRequestOrErrorResponse = validatePutRequest(input);

        if (validRequestOrErrorResponse.isFailure()) {
            return validRequestOrErrorResponse.getFailure();
        }

        LocaleHelper.SupportedLanguage userLanguage =
                matchSupportedLanguage(
                        getUserLanguageFromRequestHeaders(
                                input.getHeaders(), configurationService));

        var putRequest = validRequestOrErrorResponse.getSuccess();

        if (putRequest
                .request()
                .mfaMethod()
                .priorityIdentifier()
                .toString()
                .equalsIgnoreCase(PriorityIdentifier.DEFAULT.name())) {
            var maybeMigrationErrorResponse =
                    migrateMfaCredentialsForUserIfRequired(
                            putRequest.userProfile, mfaMethodsService, LOG);

            if (maybeMigrationErrorResponse.isPresent()) {
                return maybeMigrationErrorResponse.get();
            }

            if (putRequest.request.mfaMethod().method()
                    instanceof RequestSmsMfaDetail requestSmsMfaDetail) {
                boolean isValidOtpCode =
                        codeStorageService.isValidOtpCode(
                                putRequest.userProfile.getEmail(),
                                requestSmsMfaDetail.otp(),
                                NotificationType.VERIFY_PHONE_NUMBER);
                if (!isValidOtpCode) {
                    return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1020);
                }
            }
        }

        var updateResult =
                mfaMethodsService.updateMfaMethod(
                        putRequest.userProfile.getEmail(),
                        putRequest.mfaIdentifier,
                        putRequest.request);

        if (updateResult.isFailure()) {
            return handleUpdateMfaFailureReason(updateResult.getFailure());
        }

        var successfulUpdateMethods = updateResult.getSuccess();
        var methodsAsResponse = convertMfaMethodsToMfaMethodResponse(successfulUpdateMethods);

        if (methodsAsResponse.isFailure()) {
            LOG.error(
                    "Error converting mfa methods to response; update may still have occurred. Error: {}",
                    methodsAsResponse.getFailure());
            return generateApiGatewayProxyErrorResponse(500, ErrorResponse.ERROR_1071);
        }

        var notificationIdentifier = putRequest.request().notificationIdentifier();

        if (notificationIdentifier != null) {
            var notificationType = mapNotificationIdentifierToType(notificationIdentifier);

            if (notificationType.isFailure()) {
                return notificationType.getFailure();
            }

            sendNotification(
                    notificationType.getSuccess(), putRequest.userProfile.getEmail(), userLanguage);
        }

        try {
            return generateApiGatewayProxyResponse(200, methodsAsResponse.getSuccess(), true);
        } catch (Json.JsonException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        }
    }

    private static APIGatewayProxyResponseEvent handleUpdateMfaFailureReason(
            MfaUpdateFailureReason failureReason) {
        var response =
                switch (failureReason) {
                    case CANNOT_CHANGE_TYPE_OF_MFA_METHOD -> generateApiGatewayProxyErrorResponse(
                            400, ErrorResponse.ERROR_1072);
                    case ATTEMPT_TO_UPDATE_BACKUP_WITH_NO_DEFAULT_METHOD -> generateApiGatewayProxyErrorResponse(
                            500, ErrorResponse.ERROR_1077);
                    case CANNOT_EDIT_MFA_BACKUP_METHOD -> generateApiGatewayProxyErrorResponse(
                            400, ErrorResponse.ERROR_1077);
                    case UNEXPECTED_ERROR -> generateApiGatewayProxyErrorResponse(
                            500, ErrorResponse.ERROR_1071);
                    case UNKNOWN_MFA_IDENTIFIER -> generateApiGatewayProxyErrorResponse(
                            404, ErrorResponse.ERROR_1065);
                    case CANNOT_CHANGE_PRIORITY_OF_DEFAULT_METHOD -> generateApiGatewayProxyErrorResponse(
                            400, ErrorResponse.ERROR_1073);
                    case CANNOT_ADD_SECOND_AUTH_APP -> generateApiGatewayProxyErrorResponse(
                            400, ErrorResponse.ERROR_1082);
                    case REQUEST_TO_UPDATE_MFA_METHOD_WITH_NO_CHANGE -> generateEmptySuccessApiGatewayResponse();
                    case ATTEMPT_TO_UPDATE_PHONE_NUMBER_WITH_BACKUP_NUMBER -> generateApiGatewayProxyErrorResponse(
                            400, ErrorResponse.ERROR_1074);
                    case INVALID_PHONE_NUMBER -> generateApiGatewayProxyErrorResponse(
                            400, ErrorResponse.INVALID_PHONE_NUMBER);
                };
        if (response.getStatusCode() >= 500) {
            LOG.error("Update failed due to unexpected error {}", failureReason);
        } else if (response.getStatusCode() >= 400 && response.getStatusCode() < 500) {
            LOG.warn("Update failed due to {}", failureReason);
        } else {
            LOG.info("No update to mfa method: {}", failureReason);
        }
        return response;
    }

    private record ValidPutRequest(
            String publicSubjectId,
            String mfaIdentifier,
            UserProfile userProfile,
            MfaMethodUpdateRequest request) {}

    private Result<APIGatewayProxyResponseEvent, ValidPutRequest> validatePutRequest(
            APIGatewayProxyRequestEvent input) {
        var publicSubjectId = input.getPathParameters().get("publicSubjectId");
        var mfaIdentifier = input.getPathParameters().get("mfaIdentifier");

        if (publicSubjectId.isEmpty()) {
            LOG.error("Request does not include public subject id");
            return Result.failure(
                    generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001));
        }

        if (mfaIdentifier.isEmpty()) {
            LOG.error("Request does not include mfa identifier");
            return Result.failure(
                    generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001));
        }

        var maybeUserProfile =
                authenticationService.getOptionalUserProfileFromPublicSubject(publicSubjectId);

        if (maybeUserProfile.isEmpty()) {
            LOG.error("Unknown public subject ID");
            return Result.failure(
                    generateApiGatewayProxyErrorResponse(404, ErrorResponse.ERROR_1056));
        }

        UserProfile userProfile = maybeUserProfile.get();

        Map<String, Object> authorizerParams = input.getRequestContext().getAuthorizer();

        if (PrincipalValidationHelper.principalIsInvalid(
                userProfile,
                configurationService.getInternalSectorUri(),
                authenticationService,
                authorizerParams)) {
            return Result.failure(
                    generateApiGatewayProxyErrorResponse(401, ErrorResponse.ERROR_1079));
        }

        try {
            var mfaMethodUpdateRequest =
                    serialisationService.readValue(
                            input.getBody(), MfaMethodUpdateRequest.class, true);

            var putRequest =
                    new ValidPutRequest(
                            publicSubjectId, mfaIdentifier, userProfile, mfaMethodUpdateRequest);

            return Result.success(putRequest);
        } catch (Json.JsonException e) {
            return Result.failure(
                    generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001));
        }
    }

    private void addSessionIdToLogs(APIGatewayProxyRequestEvent input) {
        Map<String, String> headers = input.getHeaders();
        String sessionId = RequestHeaderHelper.getHeaderValueOrElse(headers, SESSION_ID_HEADER, "");
        attachSessionIdToLogs(sessionId);
    }

    private Result<APIGatewayProxyResponseEvent, NotificationType> mapNotificationIdentifierToType(
            MFAMethodNotificationIdentifier notificationIdentifier)
            throws IllegalArgumentException {
        if (notificationIdentifier == null) {
            throw new IllegalArgumentException("notificationIdentifier cannot be null.");
        }

        return switch (notificationIdentifier) {
            case CHANGED_AUTHENTICATOR_APP -> Result.success(
                    NotificationType.CHANGED_AUTHENTICATOR_APP);
            case CHANGED_DEFAULT_MFA -> Result.success(NotificationType.CHANGED_DEFAULT_MFA);
            case SWITCHED_MFA_METHODS -> Result.success(NotificationType.SWITCHED_MFA_METHODS);
            default -> {
                LOG.error(
                        "Notification identifier '{}' is not supported by the PUT endpoint.",
                        notificationIdentifier.getValue());
                yield Result.failure(
                        generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1087));
            }
        };
    }

    private void sendNotification(
            NotificationType notificationType,
            String userEmail,
            LocaleHelper.SupportedLanguage userLanguage)
            throws Json.JsonException {
        LOG.info(
                "Backup method updated successfully (notification type: '{}'). Adding confirmation message to SQS queue.",
                notificationType.name());

        NotifyRequest notifyRequest = new NotifyRequest(userEmail, notificationType, userLanguage);
        sqsClient.send(objectMapper.writeValueAsString((notifyRequest)));

        LOG.info(
                "Message successfully added to queue (notification type: '{}'). Generating successful response.",
                notificationType.name());
    }
}

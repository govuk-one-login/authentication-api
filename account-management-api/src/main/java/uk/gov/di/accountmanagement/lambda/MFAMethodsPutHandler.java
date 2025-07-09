package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent;
import uk.gov.di.accountmanagement.entity.NotificationType;
import uk.gov.di.accountmanagement.entity.NotifyRequest;
import uk.gov.di.accountmanagement.helpers.AuditHelper;
import uk.gov.di.accountmanagement.helpers.PrincipalValidationHelper;
import uk.gov.di.accountmanagement.services.AwsSqsClient;
import uk.gov.di.accountmanagement.services.CodeStorageService;
import uk.gov.di.accountmanagement.services.MfaMethodsMigrationService;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodUpdateIdentifier;
import uk.gov.di.authentication.shared.entity.mfa.request.MfaMethodUpdateRequest;
import uk.gov.di.authentication.shared.entity.mfa.request.RequestSmsMfaDetail;
import uk.gov.di.authentication.shared.helpers.ClientSessionIdHelper;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.LocaleHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.helpers.RequestHeaderHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.shared.services.mfa.MFAMethodsService;
import uk.gov.di.authentication.shared.services.mfa.MfaUpdateFailure;

import java.util.List;
import java.util.Map;

import static uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent.AUTH_INVALID_CODE_SENT;
import static uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent.AUTH_MFA_METHOD_SWITCH_COMPLETED;
import static uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent.AUTH_MFA_METHOD_SWITCH_FAILED;
import static uk.gov.di.accountmanagement.helpers.MfaMethodResponseConverterHelper.convertMfaMethodsToMfaMethodResponse;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_JOURNEY_TYPE;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_MFA_METHOD;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_MFA_TYPE;
import static uk.gov.di.authentication.shared.domain.RequestHeaders.SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.entity.AuthSessionItem.ATTRIBUTE_CLIENT_ID;
import static uk.gov.di.authentication.shared.entity.PriorityIdentifier.DEFAULT;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateEmptySuccessApiGatewayResponse;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.authentication.shared.helpers.LocaleHelper.getUserLanguageFromRequestHeaders;
import static uk.gov.di.authentication.shared.helpers.LocaleHelper.matchSupportedLanguage;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachSessionIdToLogs;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;

public class MFAMethodsPutHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(MFAMethodsPutHandler.class);
    private final ConfigurationService configurationService;
    private final CodeStorageService codeStorageService;
    private final MFAMethodsService mfaMethodsService;
    private final AuthenticationService authenticationService;
    private final AwsSqsClient sqsClient;
    private final MfaMethodsMigrationService mfaMethodsMigrationService;
    private final AuditService auditService;
    private final DynamoService dynamoService;

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
        this.auditService = new AuditService(configurationService);
        this.dynamoService = new DynamoService(configurationService);
        this.mfaMethodsMigrationService = new MfaMethodsMigrationService(configurationService);
    }

    public MFAMethodsPutHandler(
            ConfigurationService configurationService,
            MFAMethodsService mfaMethodsService,
            AuthenticationService authenticationService,
            CodeStorageService codeStorageService,
            AwsSqsClient sqsClient,
            AuditService auditService,
            DynamoService dynamoService,
            MfaMethodsMigrationService mfaMethodsMigrationService) {
        this.configurationService = configurationService;
        this.mfaMethodsService = mfaMethodsService;
        this.authenticationService = authenticationService;
        this.codeStorageService = codeStorageService;
        this.sqsClient = sqsClient;
        this.auditService = auditService;
        this.dynamoService = dynamoService;
        this.mfaMethodsMigrationService = mfaMethodsMigrationService;
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

        var putRequest = validRequestOrErrorResponse.getSuccess();

        LocaleHelper.SupportedLanguage userLanguage =
                matchSupportedLanguage(
                        getUserLanguageFromRequestHeaders(
                                input.getHeaders(), configurationService));

        if (putRequest
                .request()
                .mfaMethod()
                .priorityIdentifier()
                .toString()
                .equalsIgnoreCase(PriorityIdentifier.DEFAULT.name())) {
            var maybeMigrationErrorResponse =
                    mfaMethodsMigrationService.migrateMfaCredentialsForUserIfRequired(
                            putRequest.userProfile,
                            LOG,
                            input,
                            putRequest.request.mfaMethod().method());

            putRequest.request.mfaMethod();

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
                    var maybeAuditContext =
                            AuditHelper.buildAuditContext(
                                    configurationService,
                                    dynamoService,
                                    input,
                                    putRequest.userProfile);

                    if (maybeAuditContext.isFailure()) {
                        return generateApiGatewayProxyErrorResponse(
                                401, maybeAuditContext.getFailure());
                    }

                    var auditContext =
                            maybeAuditContext
                                    .getSuccess()
                                    .withMetadataItem(
                                            pair(
                                                    AUDIT_EVENT_EXTENSIONS_MFA_METHOD,
                                                    PriorityIdentifier.DEFAULT
                                                            .name()
                                                            .toLowerCase()));

                    auditService.submitAuditEvent(AUTH_INVALID_CODE_SENT, auditContext);

                    return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1020);
                }
            }
        }

        var maybeUpdateResult =
                mfaMethodsService.updateMfaMethod(
                        putRequest.userProfile.getEmail(),
                        putRequest.mfaIdentifier,
                        putRequest.request);

        if (maybeUpdateResult.isFailure()) {
            return handleUpdateMfaFailureReason(
                    maybeUpdateResult.getFailure(), input, putRequest.userProfile);
        }

        var updateResult = maybeUpdateResult.getSuccess();

        var successfulUpdateMethods = updateResult.mfaMethods();
        var methodsAsResponse = convertMfaMethodsToMfaMethodResponse(successfulUpdateMethods);

        if (methodsAsResponse.isFailure()) {
            LOG.error(
                    "Error converting mfa methods to response; update may still have occurred. Error: {}",
                    methodsAsResponse.getFailure());
            return generateApiGatewayProxyErrorResponse(500, ErrorResponse.ERROR_1071);
        }

        var updateTypeIdentifier = updateResult.updateTypeIdentifier();

        if (updateTypeIdentifier != null) {
            var emailNotificationType = mapEmailNotificationIdentifierToType(updateTypeIdentifier);

            sendEmailNotification(
                    emailNotificationType, putRequest.userProfile.getEmail(), userLanguage);

            var postUpdateDefaultMfaMethod =
                    successfulUpdateMethods.stream()
                            .filter(mfaMethod -> DEFAULT.name().equals(mfaMethod.getPriority()))
                            .findFirst()
                            .orElseThrow();

            if (updateTypeIdentifier == MFAMethodUpdateIdentifier.SWITCHED_MFA_METHODS) {
                var maybeAuditEventStatus =
                        sendAuditEvent(
                                AUTH_MFA_METHOD_SWITCH_COMPLETED,
                                input,
                                putRequest.userProfile,
                                postUpdateDefaultMfaMethod);

                if (maybeAuditEventStatus.isFailure()) {
                    return maybeAuditEventStatus.getFailure();
                }
            }
        } else {
            LOG.warn(
                    "Update operation completed successfully. Email notification could not be sent due to missing or invalid notification ID in service response.");
        }

        try {
            return generateApiGatewayProxyResponse(200, methodsAsResponse.getSuccess(), true);
        } catch (Json.JsonException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        }
    }

    private APIGatewayProxyResponseEvent handleUpdateMfaFailureReason(
            MfaUpdateFailure failure, APIGatewayProxyRequestEvent input, UserProfile userProfile) {
        var failureReason = failure.failureReason();
        var updateType = failure.updateTypeIdentifier();
        var mfaMethodToBeUpdated = failure.mfaMethodToUpdate();
        var response =
                switch (failureReason) {
                    case CANNOT_CHANGE_TYPE_OF_MFA_METHOD -> generateApiGatewayProxyErrorResponse(
                            400, ErrorResponse.ERROR_1072);
                    case ATTEMPT_TO_UPDATE_BACKUP_WITH_NO_DEFAULT_METHOD -> generateApiGatewayProxyErrorResponse(
                            500, ErrorResponse.ERROR_1077);
                    case CANNOT_EDIT_MFA_BACKUP_METHOD -> generateApiGatewayProxyErrorResponse(
                            400, ErrorResponse.ERROR_1077);
                    case UNEXPECTED_ERROR -> {
                        if (updateType != null
                                && updateType.equals(
                                        MFAMethodUpdateIdentifier.SWITCHED_MFA_METHODS)) {
                            sendAuditEvent(
                                    AUTH_MFA_METHOD_SWITCH_FAILED,
                                    input,
                                    userProfile,
                                    mfaMethodToBeUpdated);
                        }
                        yield generateApiGatewayProxyErrorResponse(500, ErrorResponse.ERROR_1071);
                    }
                    case UNKOWN_MFA_IDENTIFIER -> generateApiGatewayProxyErrorResponse(
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

    private NotificationType mapEmailNotificationIdentifierToType(
            MFAMethodUpdateIdentifier emailNotificationIdentifier) throws IllegalArgumentException {
        if (emailNotificationIdentifier == null) {
            throw new IllegalArgumentException("emailNotificationIdentifier cannot be null.");
        }

        return switch (emailNotificationIdentifier) {
            case CHANGED_AUTHENTICATOR_APP -> NotificationType.CHANGED_AUTHENTICATOR_APP;
            case CHANGED_SMS -> NotificationType.PHONE_NUMBER_UPDATED;
            case CHANGED_DEFAULT_MFA -> NotificationType.CHANGED_DEFAULT_MFA;
            case SWITCHED_MFA_METHODS -> NotificationType.SWITCHED_MFA_METHODS;
            default -> throw new IllegalArgumentException(
                    "Email notification identifier '"
                            + emailNotificationIdentifier.getValue()
                            + "' is not supported by the PUT endpoint.");
        };
    }

    private void sendEmailNotification(
            NotificationType notificationType,
            String userEmail,
            LocaleHelper.SupportedLanguage userLanguage)
            throws Json.JsonException {
        if (notificationType == null) {
            throw new IllegalArgumentException("notificationType cannot be null.");
        }

        LOG.info(
                "Method updated successfully (notification type: '{}'). Adding confirmation message to SQS queue.",
                notificationType.name());

        NotifyRequest notifyRequest = new NotifyRequest(userEmail, notificationType, userLanguage);
        sqsClient.send(serialisationService.writeValueAsString((notifyRequest)));

        LOG.info(
                "Message successfully added to queue (notification type: '{}'). Generating successful response.",
                notificationType.name());
    }

    private Result<APIGatewayProxyResponseEvent, Void> sendAuditEvent(
            AccountManagementAuditableEvent auditEvent,
            APIGatewayProxyRequestEvent input,
            UserProfile userProfile,
            MFAMethod mfaMethod) {
        var maybeAuditContext = buildAuditContext(auditEvent, input, userProfile, mfaMethod);

        if (maybeAuditContext.isFailure()) {
            return Result.failure(
                    generateApiGatewayProxyErrorResponse(500, maybeAuditContext.getFailure()));
        }

        auditService.submitAuditEvent(auditEvent, maybeAuditContext.getSuccess());

        LOG.info("Successfully submitted audit event: {}", auditEvent.name());
        return Result.success(null);
    }

    private Result<ErrorResponse, AuditContext> buildAuditContext(
            AccountManagementAuditableEvent auditEvent,
            APIGatewayProxyRequestEvent input,
            UserProfile userProfile,
            MFAMethod mfaMethod) {
        try {
            var phoneNumber =
                    mfaMethod.getMfaMethodType().equals(MFAMethodType.SMS.getValue())
                            ? mfaMethod.getDestination()
                            : AuditService.UNKNOWN;

            var initialMetadataPairs =
                    new AuditService.MetadataPair[] {
                        pair(
                                AUDIT_EVENT_EXTENSIONS_JOURNEY_TYPE,
                                JourneyType.ACCOUNT_MANAGEMENT.getValue()),
                        pair(AUDIT_EVENT_EXTENSIONS_MFA_TYPE, mfaMethod.getMfaMethodType())
                    };

            var context =
                    new AuditContext(
                            input.getRequestContext()
                                    .getAuthorizer()
                                    .getOrDefault(ATTRIBUTE_CLIENT_ID, AuditService.UNKNOWN)
                                    .toString(),
                            ClientSessionIdHelper.extractSessionIdFromHeaders(input.getHeaders()),
                            RequestHeaderHelper.getHeaderValueOrElse(
                                    input.getHeaders(), SESSION_ID_HEADER, ""),
                            ClientSubjectHelper.getSubjectWithSectorIdentifier(
                                            userProfile,
                                            configurationService.getInternalSectorUri(),
                                            authenticationService)
                                    .getValue(),
                            userProfile.getEmail(),
                            IpAddressHelper.extractIpAddress(input),
                            phoneNumber,
                            PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders()),
                            AuditHelper.getTxmaAuditEncoded(input.getHeaders()),
                            List.of(initialMetadataPairs));

            if (auditEvent.equals(AUTH_MFA_METHOD_SWITCH_FAILED)) {
                context =
                        context.withMetadataItem(
                                pair(
                                        AUDIT_EVENT_EXTENSIONS_MFA_METHOD,
                                        mfaMethod.getPriority().toLowerCase()));
            }

            return Result.success(context);
        } catch (Exception e) {
            LOG.error("Error building audit context", e);
            return Result.failure(ErrorResponse.ERROR_1071);
        }
    }
}

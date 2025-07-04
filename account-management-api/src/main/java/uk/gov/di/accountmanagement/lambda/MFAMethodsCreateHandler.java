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
import uk.gov.di.accountmanagement.entity.mfa.response.MfaMethodResponse;
import uk.gov.di.accountmanagement.helpers.AuditHelper;
import uk.gov.di.accountmanagement.helpers.PrincipalValidationHelper;
import uk.gov.di.accountmanagement.services.AwsSqsClient;
import uk.gov.di.accountmanagement.services.CodeStorageService;
import uk.gov.di.accountmanagement.services.MfaMethodsMigrationService;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.entity.mfa.request.MfaMethodCreateRequest;
import uk.gov.di.authentication.shared.entity.mfa.request.RequestSmsMfaDetail;
import uk.gov.di.authentication.shared.helpers.LocaleHelper;
import uk.gov.di.authentication.shared.helpers.RequestHeaderHelper;
import uk.gov.di.authentication.shared.helpers.ValidationHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.shared.services.mfa.MFAMethodsService;
import uk.gov.di.authentication.shared.services.mfa.MfaCreateFailureReason;

import java.util.Map;
import java.util.Optional;

import static uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent.AUTH_CODE_VERIFIED;
import static uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent.AUTH_INVALID_CODE_SENT;
import static uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent.AUTH_MFA_METHOD_ADD_COMPLETED;
import static uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent.AUTH_MFA_METHOD_ADD_FAILED;
import static uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent.AUTH_UPDATE_PHONE_NUMBER;
import static uk.gov.di.authentication.entity.Environment.PRODUCTION;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_MFA_METHOD;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_MFA_TYPE;
import static uk.gov.di.authentication.shared.domain.RequestHeaders.SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.DEFAULT_MFA_ALREADY_EXISTS;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.INVALID_OTP;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.REQUEST_MISSING_PARAMS;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.UNEXPECTED_ACCT_MGMT_ERROR;
import static uk.gov.di.authentication.shared.entity.JourneyType.ACCOUNT_MANAGEMENT;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.authentication.shared.helpers.LocaleHelper.getUserLanguageFromRequestHeaders;
import static uk.gov.di.authentication.shared.helpers.LocaleHelper.matchSupportedLanguage;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachTraceId;

public class MFAMethodsCreateHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final Json objectMapper = SerializationService.getInstance();

    private final ConfigurationService configurationService;
    private final CodeStorageService codeStorageService;
    private final MFAMethodsService mfaMethodsService;
    private final DynamoService dynamoService;
    private final AwsSqsClient sqsClient;
    private final AuditService auditService;
    private final CloudwatchMetricsService cloudwatchMetricsService;
    private final MfaMethodsMigrationService mfaMethodsMigrationService;
    private static final Logger LOG = LogManager.getLogger(MFAMethodsCreateHandler.class);

    public MFAMethodsCreateHandler() {
        this(ConfigurationService.getInstance());
    }

    public MFAMethodsCreateHandler(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.mfaMethodsService = new MFAMethodsService(configurationService);
        this.dynamoService = new DynamoService(configurationService);
        this.codeStorageService =
                new CodeStorageService(new RedisConnectionService(configurationService));
        this.sqsClient =
                new AwsSqsClient(
                        configurationService.getAwsRegion(),
                        configurationService.getEmailQueueUri(),
                        configurationService.getSqsEndpointUri());
        this.cloudwatchMetricsService = new CloudwatchMetricsService(configurationService);
        this.auditService = new AuditService(configurationService);
        this.mfaMethodsMigrationService = new MfaMethodsMigrationService(configurationService);
    }

    public MFAMethodsCreateHandler(
            ConfigurationService configurationService,
            MFAMethodsService mfaMethodsService,
            DynamoService dynamoService,
            CodeStorageService codeStorageService,
            AuditService auditService,
            AwsSqsClient sqsClient,
            CloudwatchMetricsService cloudwatchMetricsService,
            MfaMethodsMigrationService mfaMethodsMigrationService) {
        this.configurationService = configurationService;
        this.mfaMethodsService = mfaMethodsService;
        this.dynamoService = dynamoService;
        this.codeStorageService = codeStorageService;
        this.sqsClient = sqsClient;
        this.auditService = auditService;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
        this.mfaMethodsMigrationService = mfaMethodsMigrationService;
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        ThreadContext.clearMap();
        attachTraceId();
        return segmentedFunctionCall(
                "account-management-api::" + getClass().getSimpleName(),
                () -> mfaMethodsHandler(input, context));
    }

    private Result<APIGatewayProxyResponseEvent, UserProfile>
            getUserProfileWhenGuardConditionsPassed(APIGatewayProxyRequestEvent input) {
        if (!configurationService.isMfaMethodManagementApiEnabled()) {
            LOG.error(
                    "Request to create MFA method in {} environment but feature is switched off.",
                    configurationService.getEnvironment());
            return Result.failure(
                    generateApiGatewayProxyErrorResponse(400, ErrorResponse.MM_API_NOT_AVAILABLE));
        }

        var subject = input.getPathParameters().get("publicSubjectId");

        if (subject == null) {
            LOG.error("Subject missing from request prevents request being handled.");
            return Result.failure(
                    generateApiGatewayProxyErrorResponse(400, REQUEST_MISSING_PARAMS));
        }

        Optional<UserProfile> maybeUserProfile =
                dynamoService.getOptionalUserProfileFromPublicSubject(subject);
        if (maybeUserProfile.isEmpty()) {
            return Result.failure(
                    generateApiGatewayProxyErrorResponse(404, ErrorResponse.USER_NOT_FOUND));
        }

        UserProfile userProfile = maybeUserProfile.get();

        Map<String, Object> authorizerParams = input.getRequestContext().getAuthorizer();

        if (PrincipalValidationHelper.principalIsInvalid(
                userProfile,
                configurationService.getInternalSectorUri(),
                dynamoService,
                authorizerParams)) {
            return Result.failure(
                    generateApiGatewayProxyErrorResponse(401, ErrorResponse.INVALID_PRINCIPAL));
        }

        return Result.success(userProfile);
    }

    private Result<ErrorResponse, MfaMethodCreateRequest> validateRequest(
            APIGatewayProxyRequestEvent input, UserProfile userProfile) {
        MfaMethodCreateRequest mfaMethodCreateRequest = null;

        try {
            mfaMethodCreateRequest = readMfaMethodCreateRequest(input);
        } catch (Json.JsonException e) {
            LOG.error("Invalid request to create an MFA method: ", e);
            return Result.failure(REQUEST_MISSING_PARAMS);
        }

        if (mfaMethodCreateRequest.mfaMethod().priorityIdentifier() == PriorityIdentifier.DEFAULT) {
            LOG.error(DEFAULT_MFA_ALREADY_EXISTS.name());
            return Result.failure(DEFAULT_MFA_ALREADY_EXISTS);
        }

        if (mfaMethodCreateRequest.mfaMethod().method()
                instanceof RequestSmsMfaDetail requestSmsMfaDetail) {

            var invalidPhoneNumber =
                    ValidationHelper.validatePhoneNumber(
                            requestSmsMfaDetail.phoneNumber(), PRODUCTION.name(), false);

            if (invalidPhoneNumber.isPresent()) {
                var auditEventStatus =
                        sendAuditEvent(
                                AUTH_MFA_METHOD_ADD_FAILED,
                                input,
                                userProfile,
                                mfaMethodCreateRequest);
                if (auditEventStatus.isFailure()) {
                    LOG.error(auditEventStatus.getFailure());
                }
                return Result.failure(invalidPhoneNumber.get());
            }

            boolean isValidOtpCode =
                    codeStorageService.isValidOtpCode(
                            userProfile.getEmail(),
                            requestSmsMfaDetail.otp(),
                            NotificationType.VERIFY_PHONE_NUMBER);
            if (!isValidOtpCode) {
                LOG.info("Invalid OTP presented.");
                var auditEventStatus =
                        sendAuditEvent(
                                AUTH_INVALID_CODE_SENT, input, userProfile, mfaMethodCreateRequest);
                if (auditEventStatus.isFailure()) {
                    LOG.error(auditEventStatus.getFailure());
                }
                return Result.failure(INVALID_OTP);
            }
        }

        return Result.success(mfaMethodCreateRequest);
    }

    private APIGatewayProxyResponseEvent mfaMethodsHandler(
            APIGatewayProxyRequestEvent input, Context context) {

        addSessionIdToLogs(input);

        var maybePassedGuardConditions = getUserProfileWhenGuardConditionsPassed(input);

        if (maybePassedGuardConditions.isFailure()) {
            return maybePassedGuardConditions.getFailure();
        }

        LOG.info("Request passed guard conditions");

        var userProfile = maybePassedGuardConditions.getSuccess();

        var maybeValidRequest = validateRequest(input, userProfile);

        if (maybeValidRequest.isFailure()) {
            return generateApiGatewayProxyErrorResponse(400, maybeValidRequest.getFailure());
        }

        MfaMethodCreateRequest mfaMethodCreateRequest = maybeValidRequest.getSuccess();

        var auditEventStatus =
                sendAuditEvent(AUTH_CODE_VERIFIED, input, userProfile, mfaMethodCreateRequest);
        if (auditEventStatus.isFailure()) {
            LOG.error(auditEventStatus.getFailure());
            return generateApiGatewayProxyErrorResponse(500, auditEventStatus.getFailure());
        }

        var maybeMigrationErrorResponse =
                mfaMethodsMigrationService.migrateMfaCredentialsForUserIfRequired(
                        userProfile, LOG, input, mfaMethodCreateRequest.mfaMethod().method());

        if (maybeMigrationErrorResponse.isPresent()) {
            return maybeMigrationErrorResponse.get();
        }

        Result<MfaCreateFailureReason, MFAMethod> addBackupMfaResult =
                mfaMethodsService.addBackupMfa(
                        userProfile.getEmail(), mfaMethodCreateRequest.mfaMethod());

        if (addBackupMfaResult.isFailure()) {
            auditEventStatus =
                    sendAuditEvent(
                            AUTH_MFA_METHOD_ADD_FAILED, input, userProfile, mfaMethodCreateRequest);
            if (auditEventStatus.isFailure()) {
                LOG.error(auditEventStatus.getFailure());
                return generateApiGatewayProxyErrorResponse(500, auditEventStatus.getFailure());
            }
            return handleCreateBackupMfaFailure(addBackupMfaResult.getFailure());
        }

        var backupMfaMethod = addBackupMfaResult.getSuccess();
        var backupMfaMethodAsResponse = MfaMethodResponse.from(backupMfaMethod);

        if (backupMfaMethodAsResponse.isFailure()) {
            LOG.error(backupMfaMethodAsResponse.getFailure());
            auditEventStatus =
                    sendAuditEvent(
                            AUTH_MFA_METHOD_ADD_FAILED, input, userProfile, mfaMethodCreateRequest);
            if (auditEventStatus.isFailure()) {
                LOG.error(auditEventStatus.getFailure());
                return generateApiGatewayProxyErrorResponse(500, auditEventStatus.getFailure());
            }
            return generateApiGatewayProxyErrorResponse(500, UNEXPECTED_ACCT_MGMT_ERROR);
        }

        Result<ErrorResponse, AuditContext> auditContextResult =
                buildAuditContext(AUTH_MFA_METHOD_ADD_COMPLETED, input, userProfile, mfaMethodCreateRequest);

        if (auditContextResult.isFailure()) {
            return generateApiGatewayProxyErrorResponse(401, auditContextResult.getFailure());
        }

        var auditContext = auditContextResult.getSuccess();

        var addCompletedAuditContext =
                auditContext.withMetadataItem(
                        pair(
                                AUDIT_EVENT_EXTENSIONS_MFA_TYPE,
                                mfaMethodCreateRequest
                                        .mfaMethod()
                                        .method()
                                        .mfaMethodType()
                                        .toString()));

        if (mfaMethodCreateRequest.mfaMethod().method()
                instanceof RequestSmsMfaDetail requestSmsMfaDetail) {
            addCompletedAuditContext =
                    addCompletedAuditContext.withPhoneNumber(requestSmsMfaDetail.phoneNumber());
        }

        auditService.submitAuditEvent(AUTH_MFA_METHOD_ADD_COMPLETED, auditContext);

        if (auditEventStatus.isFailure()) {
            LOG.error(auditEventStatus.getFailure());
            return generateApiGatewayProxyErrorResponse(500, auditEventStatus.getFailure());
        }

        if (backupMfaMethod.getMfaMethodType().equalsIgnoreCase(MFAMethodType.SMS.name())) {
            var updatePhoneNumberAuditContext =
                    auditContext.withMetadataItem(
                            pair(
                                    AUDIT_EVENT_EXTENSIONS_MFA_METHOD,
                                    mfaMethodCreateRequest
                                            .mfaMethod()
                                            .priorityIdentifier()
                                            .name()
                                            .toLowerCase()));

            auditService.submitAuditEvent(AUTH_UPDATE_PHONE_NUMBER, updatePhoneNumberAuditContext);
        }

        LocaleHelper.SupportedLanguage userLanguage =
                matchSupportedLanguage(
                        getUserLanguageFromRequestHeaders(
                                input.getHeaders(), configurationService));

        LOG.info("Backup method added successfully. Adding confirmation message to SQS queue");

        NotifyRequest notifyRequest =
                new NotifyRequest(
                        userProfile.getEmail(), NotificationType.BACKUP_METHOD_ADDED, userLanguage);

        try {
            sqsClient.send(objectMapper.writeValueAsString((notifyRequest)));
            LOG.info("Message successfully added to queue. Generating successful response");
        } catch (Json.JsonException e) {
            LOG.error("Failed to add message to queue: ", e);
            return generateApiGatewayProxyErrorResponse(500, UNEXPECTED_ACCT_MGMT_ERROR);
        }

        cloudwatchMetricsService.incrementMfaMethodCounter(
                configurationService.getEnvironment(),
                "CreateMfaMethod",
                "SUCCESS",
                ACCOUNT_MANAGEMENT,
                mfaMethodCreateRequest.mfaMethod().method().mfaMethodType().toString(),
                PriorityIdentifier.BACKUP);

        try {
            return generateApiGatewayProxyResponse(
                    200, backupMfaMethodAsResponse.getSuccess(), true);
        } catch (Json.JsonException e) {
            LOG.error("Failed to build successful response: ", e);
            return generateApiGatewayProxyErrorResponse(500, UNEXPECTED_ACCT_MGMT_ERROR);
        }
    }

    private Result<ErrorResponse, AuditContext> updateAuditContextForFailedMFACreation(
            UserProfile userProfile, AuditContext auditContext) {
        var maybeMfaMethods = mfaMethodsService.getMfaMethods(userProfile.getEmail());

        if (maybeMfaMethods.isFailure()) {
            LOG.error("No MFA methods found for user");
            return Result.failure(UNEXPECTED_ACCT_MGMT_ERROR);
        }

        var mfaMethods = maybeMfaMethods.getSuccess();

        var defaultMfaMethod =
                mfaMethods.stream()
                        .filter(
                                method ->
                                        method.getPriority()
                                                .equalsIgnoreCase(
                                                        PriorityIdentifier.DEFAULT.name()))
                        .findFirst();

        if (defaultMfaMethod.isEmpty()) {
            LOG.error("No default MFA method found for user");
            return Result.failure(UNEXPECTED_ACCT_MGMT_ERROR);
        }

        if (defaultMfaMethod.get().getMfaMethodType().equalsIgnoreCase(MFAMethodType.SMS.name())) {
            auditContext = auditContext.withPhoneNumber(defaultMfaMethod.get().getDestination());
        }

        auditContext =
                auditContext.withMetadataItem(
                        pair(
                                AUDIT_EVENT_EXTENSIONS_MFA_TYPE,
                                defaultMfaMethod.get().getMfaMethodType()));
        auditContext =
                auditContext.withMetadataItem(
                        pair(
                                AUDIT_EVENT_EXTENSIONS_MFA_METHOD,
                                PriorityIdentifier.DEFAULT.name().toLowerCase()));
        return Result.success(auditContext);
    }

    private static APIGatewayProxyResponseEvent handleCreateBackupMfaFailure(
            MfaCreateFailureReason failureReason) {
        return switch (failureReason) {
            case BACKUP_AND_DEFAULT_METHOD_ALREADY_EXIST -> generateApiGatewayProxyErrorResponse(
                    400, ErrorResponse.MFA_METHOD_COUNT_LIMIT_REACHED);
            case PHONE_NUMBER_ALREADY_EXISTS -> generateApiGatewayProxyErrorResponse(
                    400, ErrorResponse.SMS_MFA_WITH_NUMBER_EXISTS);
            case AUTH_APP_EXISTS -> generateApiGatewayProxyErrorResponse(
                    400, ErrorResponse.AUTH_APP_EXISTS);
            case INVALID_PHONE_NUMBER -> generateApiGatewayProxyErrorResponse(
                    400, ErrorResponse.INVALID_PHONE_NUMBER);
        };
    }

    private Result<ErrorResponse, AuditContext> buildAuditContext(
            AccountManagementAuditableEvent auditEvent,
            APIGatewayProxyRequestEvent input,
            UserProfile userProfile,
            MfaMethodCreateRequest mfaMethodCreateRequest) {
        if (auditEvent.equals(AUTH_MFA_METHOD_ADD_FAILED)) {
            var baseContextResult =
                    AuditHelper.buildAuditContext(
                            configurationService, dynamoService, input, userProfile);
            if (baseContextResult.isFailure()) {
                return baseContextResult;
            }
            return AuditHelper.updateAuditContextForFailedMFACreation(
                    userProfile, baseContextResult.getSuccess(), mfaMethodsService, LOG);
        } else {
            return AuditHelper.buildAuditContextForMfa(
                    auditEvent,
                    input,
                    userProfile,
                    mfaMethodCreateRequest,
                    configurationService,
                    dynamoService,
                    LOG);
        }
    }

    private Result<ErrorResponse, Void> sendAuditEvent(
            AccountManagementAuditableEvent auditEvent,
            APIGatewayProxyRequestEvent input,
            UserProfile userProfile,
            MfaMethodCreateRequest mfaMethodCreateRequest) {
        var maybeAuditContext =
                buildAuditContext(auditEvent, input, userProfile, mfaMethodCreateRequest);
        if (maybeAuditContext.isFailure()) {
            LOG.error(
                    "Error when building audit context for {} audit event with error code {}. No event raised",
                    auditEvent,
                    maybeAuditContext.getFailure());
            return Result.failure(ErrorResponse.FAILED_TO_RAISE_AUDIT_EVENT);
        }

        return AuditHelper.sendAuditEvent(
                auditEvent, maybeAuditContext.getSuccess(), auditService, LOG);
    }

    private void addSessionIdToLogs(APIGatewayProxyRequestEvent input) {
        Map<String, String> headers = input.getHeaders();
        String sessionId = RequestHeaderHelper.getHeaderValueOrElse(headers, SESSION_ID_HEADER, "");
        uk.gov.di.authentication.shared.helpers.LogLineHelper.attachSessionIdToLogs(sessionId);
    }

    private MfaMethodCreateRequest readMfaMethodCreateRequest(APIGatewayProxyRequestEvent input)
            throws Json.JsonException {

        MfaMethodCreateRequest mfaMethodCreateRequest;
        try {
            mfaMethodCreateRequest =
                    segmentedFunctionCall(
                            "SerializationService::GSON::fromJson",
                            () ->
                                    objectMapper.readValue(
                                            input.getBody(), MfaMethodCreateRequest.class, true));

        } catch (RuntimeException e) {
            LOG.error("Error during JSON deserialization", e);
            throw new Json.JsonException(e);
        }
        return mfaMethodCreateRequest;
    }
}

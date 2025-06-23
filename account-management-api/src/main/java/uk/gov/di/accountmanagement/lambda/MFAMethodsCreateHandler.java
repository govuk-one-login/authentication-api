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
import uk.gov.di.accountmanagement.entity.mfa.response.MfaMethodResponse;
import uk.gov.di.accountmanagement.helpers.AuditHelper;
import uk.gov.di.accountmanagement.helpers.PrincipalValidationHelper;
import uk.gov.di.accountmanagement.services.AwsSqsClient;
import uk.gov.di.accountmanagement.services.CodeStorageService;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.shared.conditions.MfaHelper;
import uk.gov.di.authentication.shared.entity.*;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.entity.mfa.request.MfaMethodCreateRequest;
import uk.gov.di.authentication.shared.entity.mfa.request.RequestSmsMfaDetail;
import uk.gov.di.authentication.shared.helpers.*;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.shared.services.mfa.MFAMethodsService;
import uk.gov.di.authentication.shared.services.mfa.MfaCreateFailureReason;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent.AUTH_MFA_METHOD_ADD_FAILED;
import static uk.gov.di.accountmanagement.helpers.MfaMethodsMigrationHelper.migrateMfaCredentialsForUserIfRequired;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_JOURNEY_TYPE;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_MFA_METHOD;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_MFA_TYPE;
import static uk.gov.di.authentication.shared.domain.RequestHeaders.SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.entity.AuthSessionItem.ATTRIBUTE_CLIENT_ID;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1079;
import static uk.gov.di.authentication.shared.entity.JourneyType.ACCOUNT_MANAGEMENT;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.authentication.shared.helpers.LocaleHelper.getUserLanguageFromRequestHeaders;
import static uk.gov.di.authentication.shared.helpers.LocaleHelper.matchSupportedLanguage;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;

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
    }

    public MFAMethodsCreateHandler(
            ConfigurationService configurationService,
            MFAMethodsService mfaMethodsService,
            DynamoService dynamoService,
            CodeStorageService codeStorageService,
            AuditService auditService,
            AwsSqsClient sqsClient,
            CloudwatchMetricsService cloudwatchMetricsService) {
        this.configurationService = configurationService;
        this.mfaMethodsService = mfaMethodsService;
        this.dynamoService = dynamoService;
        this.codeStorageService = codeStorageService;
        this.sqsClient = sqsClient;
        this.auditService = auditService;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        ThreadContext.clearMap();
        return segmentedFunctionCall(
                "account-management-api::" + getClass().getSimpleName(),
                () -> mfaMethodsHandler(input, context));
    }

    private APIGatewayProxyResponseEvent mfaMethodsHandler(
            APIGatewayProxyRequestEvent input, Context context) {

        if (!configurationService.isMfaMethodManagementApiEnabled()) {
            LOG.error(
                    "Request to create MFA method in {} environment but feature is switched off.",
                    configurationService.getEnvironment());
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1063);
        }

        var subject = input.getPathParameters().get("publicSubjectId");

        if (subject == null) {
            LOG.error("Subject missing from request prevents request being handled.");
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        }

        Optional<UserProfile> maybeUserProfile =
                dynamoService.getOptionalUserProfileFromPublicSubject(subject);
        if (maybeUserProfile.isEmpty()) {
            return generateApiGatewayProxyErrorResponse(404, ErrorResponse.ERROR_1056);
        }
        UserProfile userProfile = maybeUserProfile.get();

        var maybeMigrationErrorResponse =
                migrateMfaCredentialsForUserIfRequired(userProfile, mfaMethodsService, LOG);

        if (maybeMigrationErrorResponse.isPresent()) return maybeMigrationErrorResponse.get();

        MfaMethodCreateRequest mfaMethodCreateRequest = null;
        try {
            mfaMethodCreateRequest = readMfaMethodCreateRequest(input);
        } catch (Json.JsonException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        }

        if (mfaMethodCreateRequest.mfaMethod().priorityIdentifier() == PriorityIdentifier.DEFAULT) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1080);
        }

        if (mfaMethodCreateRequest.mfaMethod().method()
                instanceof RequestSmsMfaDetail requestSmsMfaDetail) {
            boolean isValidOtpCode =
                    codeStorageService.isValidOtpCode(
                            userProfile.getEmail(),
                            requestSmsMfaDetail.otp(),
                            NotificationType.VERIFY_PHONE_NUMBER);
            if (!isValidOtpCode) {
                return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1020);
            }
        }

        LOG.info("Update MFA POST called with: {}", mfaMethodCreateRequest);
        Result<MfaCreateFailureReason, MFAMethod> addBackupMfaResult =
                mfaMethodsService.addBackupMfa(
                        userProfile.getEmail(), mfaMethodCreateRequest.mfaMethod());

        Result<ErrorResponse, AuditContext> auditContextResult =
                buildAuditcontext(input, userProfile);

        if (auditContextResult.isFailure()) {
            return generateApiGatewayProxyErrorResponse(401, auditContextResult.getFailure());
        }

        var auditContext = auditContextResult.getSuccess();

        if (addBackupMfaResult.isFailure()) {
            auditService.submitAuditEvent(AUTH_MFA_METHOD_ADD_FAILED, auditContext);
            return handleCreateBackupMfaFailure(addBackupMfaResult.getFailure());
        }

        var backupMfaMethod = addBackupMfaResult.getSuccess();
        var backupMfaMethodAsResponse = MfaMethodResponse.from(backupMfaMethod);

        if (backupMfaMethodAsResponse.isFailure()) {
            LOG.error(backupMfaMethodAsResponse.getFailure());
            auditService.submitAuditEvent(AUTH_MFA_METHOD_ADD_FAILED, auditContext);
            return generateApiGatewayProxyErrorResponse(500, ErrorResponse.ERROR_1071);
        }

        LocaleHelper.SupportedLanguage userLanguage =
                matchSupportedLanguage(
                        getUserLanguageFromRequestHeaders(
                                input.getHeaders(), configurationService));

        LOG.info("Backup method added successfully.  Adding confirmation message to SQS queue");

        NotifyRequest notifyRequest =
                new NotifyRequest(
                        userProfile.getEmail(), NotificationType.BACKUP_METHOD_ADDED, userLanguage);

        try {
            sqsClient.send(objectMapper.writeValueAsString((notifyRequest)));
            LOG.info("Message successfully added to queue. Generating successful response");
        } catch (Json.JsonException e) {
            return generateApiGatewayProxyErrorResponse(500, ErrorResponse.ERROR_1071);
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
            return generateApiGatewayProxyErrorResponse(500, ErrorResponse.ERROR_1071);
        }
    }

    private static APIGatewayProxyResponseEvent handleCreateBackupMfaFailure(
            MfaCreateFailureReason failureReason) {
        return switch (failureReason) {
            case BACKUP_AND_DEFAULT_METHOD_ALREADY_EXIST -> generateApiGatewayProxyErrorResponse(
                    400, ErrorResponse.ERROR_1068);
            case PHONE_NUMBER_ALREADY_EXISTS -> generateApiGatewayProxyErrorResponse(
                    400, ErrorResponse.ERROR_1069);
            case AUTH_APP_EXISTS -> generateApiGatewayProxyErrorResponse(
                    400, ErrorResponse.ERROR_1070);
            case INVALID_PHONE_NUMBER -> generateApiGatewayProxyErrorResponse(
                    400, ErrorResponse.INVALID_PHONE_NUMBER);
        };
    }

    private Result<ErrorResponse, AuditContext> buildAuditcontext(
            APIGatewayProxyRequestEvent input, UserProfile userProfile) {
        try {
            Map<String, Object> authorizerParams = input.getRequestContext().getAuthorizer();

            if (PrincipalValidationHelper.principalIsInvalid(
                    userProfile,
                    configurationService.getInternalSectorUri(),
                    dynamoService,
                    authorizerParams)) {
                return Result.failure(ERROR_1079);
            }

            String currentDefaultMfaType = "NONE";

            UserCredentials userCredentials =
                    dynamoService.getUserCredentialsFromEmail(userProfile.getEmail());
            if (userProfile.isMfaMethodsMigrated()) {
                var defaultMfa = MfaHelper.getDefaultMfaMethodForMigratedUser(userCredentials);
                if (defaultMfa.isPresent()) {
                    currentDefaultMfaType = defaultMfa.get().getMfaMethodType();
                }
            } else {
                if (userProfile.isPhoneNumberVerified()) {
                    currentDefaultMfaType = MFAMethodType.SMS.name();
                } else {
                    currentDefaultMfaType = MFAMethodType.AUTH_APP.name();
                }
            }

            var metadataPairs =
                    new AuditService.MetadataPair[] {
                        pair(
                                AUDIT_EVENT_EXTENSIONS_JOURNEY_TYPE,
                                JourneyType.ACCOUNT_MANAGEMENT.getValue()),
                        pair(
                                AUDIT_EVENT_EXTENSIONS_MFA_METHOD,
                                PriorityIdentifier.DEFAULT.name().toLowerCase()),
                        pair(AUDIT_EVENT_EXTENSIONS_MFA_TYPE, currentDefaultMfaType)
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
                                            dynamoService)
                                    .getValue(),
                            userProfile.getEmail(),
                            IpAddressHelper.extractIpAddress(input),
                            userProfile.getPhoneNumber(),
                            PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders()),
                            AuditHelper.getTxmaAuditEncoded(input.getHeaders()),
                            List.of(metadataPairs));

            return Result.success(context);
        } catch (Exception e) {
            LOG.error("Error building audit context", e);
            return Result.failure(ErrorResponse.ERROR_1071);
        }
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

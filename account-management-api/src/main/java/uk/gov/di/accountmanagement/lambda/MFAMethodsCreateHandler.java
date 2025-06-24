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
import uk.gov.di.accountmanagement.helpers.PrincipalValidationHelper;
import uk.gov.di.accountmanagement.services.AwsSqsClient;
import uk.gov.di.accountmanagement.services.CodeStorageService;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.entity.mfa.request.MfaMethodCreateRequest;
import uk.gov.di.authentication.shared.entity.mfa.request.RequestSmsMfaDetail;
import uk.gov.di.authentication.shared.helpers.ClientSessionIdHelper;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.LocaleHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.helpers.PhoneNumberHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.shared.services.mfa.MFAMethodsService;
import uk.gov.di.authentication.shared.services.mfa.MfaCreateFailureReason;

import java.util.Map;
import java.util.Optional;

import static uk.gov.di.accountmanagement.helpers.MfaMethodsMigrationHelper.migrateMfaCredentialsForUserIfRequired;
import static uk.gov.di.authentication.shared.domain.RequestHeaders.SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.authentication.shared.helpers.LocaleHelper.getUserLanguageFromRequestHeaders;
import static uk.gov.di.authentication.shared.helpers.LocaleHelper.matchSupportedLanguage;
import static uk.gov.di.authentication.shared.helpers.RequestHeaderHelper.getHeaderValueOrElse;
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
        this.auditService = new AuditService(configurationService);
    }

    public MFAMethodsCreateHandler(
            ConfigurationService configurationService,
            MFAMethodsService mfaMethodsService,
            DynamoService dynamoService,
            CodeStorageService codeStorageService,
            AwsSqsClient sqsClient,
            AuditService auditService) {
        this.configurationService = configurationService;
        this.mfaMethodsService = mfaMethodsService;
        this.dynamoService = dynamoService;
        this.codeStorageService = codeStorageService;
        this.sqsClient = sqsClient;
        this.auditService = auditService;
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

        Map<String, Object> authorizerParams = input.getRequestContext().getAuthorizer();
        if (PrincipalValidationHelper.principalIsInvalid(
                userProfile,
                configurationService.getInternalSectorUri(),
                dynamoService,
                authorizerParams)) {
            return generateApiGatewayProxyErrorResponse(401, ErrorResponse.ERROR_1079);
        }

        MfaMethodCreateRequest mfaMethodCreateRequest = null;

        try {
            mfaMethodCreateRequest = readMfaMethodCreateRequest(input);
        } catch (Json.JsonException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        }

        String phoneNumber;
        // if the request is SMS then get the destination and validate as phone number
        if (mfaMethodCreateRequest.mfaMethod().method().mfaMethodType() == MFAMethodType.SMS) {
            phoneNumber =
        }



        emitAuditEvent(
                authorizerParams, userProfile, subject, input, mfaMethodCreateRequest.mfaMethod());

        var maybeMigrationErrorResponse =
                migrateMfaCredentialsForUserIfRequired(userProfile, mfaMethodsService, LOG);

        if (maybeMigrationErrorResponse.isPresent()) return maybeMigrationErrorResponse.get();








        LOG.info("Update MFA POST called with: {}", mfaMethodCreateRequest);

        if (mfaMethodCreateRequest.mfaMethod().priorityIdentifier() == PriorityIdentifier.DEFAULT) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1080);
        }


        LocaleHelper.SupportedLanguage userLanguage =
                matchSupportedLanguage(
                        getUserLanguageFromRequestHeaders(
                                input.getHeaders(), configurationService));

        try {
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

            Result<MfaCreateFailureReason, MFAMethod> addBackupMfaResult =
                    mfaMethodsService.addBackupMfa(
                            userProfile.getEmail(), mfaMethodCreateRequest.mfaMethod());

            if (addBackupMfaResult.isFailure()) {
                return handleCreateBackupMfaFailure(addBackupMfaResult.getFailure());
            }

            var backupMfaMethod = addBackupMfaResult.getSuccess();
            var backupMfaMethodAsResponse = MfaMethodResponse.from(backupMfaMethod);

            if (backupMfaMethodAsResponse.isFailure()) {
                LOG.error(backupMfaMethodAsResponse.getFailure());
                return generateApiGatewayProxyErrorResponse(500, ErrorResponse.ERROR_1071);
            }

            LOG.info("Backup method added successfully.  Adding confirmation message to SQS queue");
            NotifyRequest notifyRequest =
                    new NotifyRequest(
                            userProfile.getEmail(),
                            NotificationType.BACKUP_METHOD_ADDED,
                            userLanguage);
            sqsClient.send(objectMapper.writeValueAsString((notifyRequest)));
            LOG.info("Message successfully added to queue. Generating successful response");

            return generateApiGatewayProxyResponse(
                    200, backupMfaMethodAsResponse.getSuccess(), true);

        } catch (Json.JsonException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        }
    }

    private void emitAuditEvent(
            Map<String, Object> authorizerParams,
            UserProfile userProfile,
            String subject,
            APIGatewayProxyRequestEvent input,
            MfaMethodCreateRequest.MfaMethod mfaMethod) {

        var headers = input.getHeaders();

        String sessionId = getHeaderValueOrElse(headers, SESSION_ID_HEADER, "unknown");
        String clientSessionId =
                ClientSessionIdHelper.extractSessionIdFromHeaders(input.getHeaders());
        String ipAddress = IpAddressHelper.extractIpAddress(input);
        String persistentSessionId = PersistentIdHelper.extractPersistentIdFromHeaders(headers);

        var auditContext =
                AuditContext.emptyAuditContext()
                        .withClientId((String) authorizerParams.get("clientId"))
                        .withEmail(userProfile.getEmail())
                        .withSessionId(sessionId)
                        .withClientSessionId(clientSessionId)
                        .withIpAddress(ipAddress)
                        .withPersistentSessionId(persistentSessionId)
                        .withSubjectId(subject)
                        .withPhoneNumber(userProfile.getPhoneNumber());

        if (mfaMethod.method() instanceof RequestSmsMfaDetail requestSmsMfaDetail) {
            auditContext.withMetadataItem(
                    pair(
                            "phone_number_country_code",
                            PhoneNumberHelper.getCountry(requestSmsMfaDetail.phoneNumber())));
        }

        auditContext.withMetadataItem(pair("mfa-type", mfaMethod.method().mfaMethodType()));
        auditContext.withMetadataItem(pair("journey-type", JourneyType.ACCOUNT_MANAGEMENT));
        auditContext.withMetadataItem(pair("migration-succeeded", true));

        auditService.submitAuditEvent(
                AccountManagementAuditableEvent.AUTH_MFA_METHOD_MIGRATION_ATTEMPTED, auditContext);
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

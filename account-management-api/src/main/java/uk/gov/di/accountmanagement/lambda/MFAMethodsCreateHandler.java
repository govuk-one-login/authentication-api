package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.accountmanagement.entity.NotificationType;
import uk.gov.di.accountmanagement.entity.mfa.response.MfaMethodResponse;
import uk.gov.di.accountmanagement.helpers.PrincipalValidationHelper;
import uk.gov.di.accountmanagement.services.CodeStorageService;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.request.MfaMethodCreateOrUpdateRequest;
import uk.gov.di.authentication.shared.entity.mfa.request.RequestSmsMfaDetail;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.shared.services.mfa.MFAMethodsService;
import uk.gov.di.authentication.shared.services.mfa.MfaCreateFailureReason;
import uk.gov.di.authentication.shared.services.mfa.MfaMigrationFailureReason;

import java.util.Map;
import java.util.Optional;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;

public class MFAMethodsCreateHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final Json objectMapper = SerializationService.getInstance();

    private final ConfigurationService configurationService;
    private final CodeStorageService codeStorageService;
    private final MFAMethodsService mfaMethodsService;
    private final DynamoService dynamoService;
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
    }

    public MFAMethodsCreateHandler(
            ConfigurationService configurationService,
            MFAMethodsService mfaMethodsService,
            DynamoService dynamoService,
            CodeStorageService codeStorageService) {
        this.configurationService = configurationService;
        this.mfaMethodsService = mfaMethodsService;
        this.dynamoService = dynamoService;
        this.codeStorageService = codeStorageService;
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

        var maybeMigrationErrorResponse = migrateMfaCredentialsForUserIfRequired(userProfile);
        if (maybeMigrationErrorResponse.isPresent()) return maybeMigrationErrorResponse.get();

        try {
            MfaMethodCreateOrUpdateRequest mfaMethodCreateRequest =
                    readMfaMethodCreateRequest(input);

            LOG.info("Update MFA POST called with: {}", mfaMethodCreateRequest);

            if (mfaMethodCreateRequest.mfaMethod().priorityIdentifier()
                    == PriorityIdentifier.DEFAULT) {
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

            return generateApiGatewayProxyResponse(
                    200, backupMfaMethodAsResponse.getSuccess(), true);

        } catch (Json.JsonException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
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
                    400, ErrorResponse.ERROR_1012);
        };
    }

    private Optional<APIGatewayProxyResponseEvent> migrateMfaCredentialsForUserIfRequired(
            UserProfile userProfile) {
        if (!userProfile.getMfaMethodsMigrated()) {
            Optional<MfaMigrationFailureReason> maybeMfaMigrationFailureReason =
                    mfaMethodsService.migrateMfaCredentialsForUser(userProfile.getEmail());

            if (maybeMfaMigrationFailureReason.isPresent()) {
                MfaMigrationFailureReason mfaMigrationFailureReason =
                        maybeMfaMigrationFailureReason.get();

                LOG.warn(
                        "Failed to migrate user's MFA credentials due to {}",
                        mfaMigrationFailureReason);

                return switch (mfaMigrationFailureReason) {
                    case NO_USER_FOUND_FOR_EMAIL -> Optional.of(
                            generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1056));
                    case UNEXPECTED_ERROR_RETRIEVING_METHODS -> Optional.of(
                            generateApiGatewayProxyErrorResponse(500, ErrorResponse.ERROR_1064));
                    case ALREADY_MIGRATED -> Optional.empty();
                };
            }
        }

        return Optional.empty();
    }

    private MfaMethodCreateOrUpdateRequest readMfaMethodCreateRequest(
            APIGatewayProxyRequestEvent input) throws Json.JsonException {

        MfaMethodCreateOrUpdateRequest mfaMethodCreateRequest;
        try {
            mfaMethodCreateRequest =
                    segmentedFunctionCall(
                            "SerializationService::GSON::fromJson",
                            () ->
                                    objectMapper.readValue(
                                            input.getBody(),
                                            MfaMethodCreateOrUpdateRequest.class,
                                            true));

        } catch (RuntimeException e) {
            LOG.error("Error during JSON deserialization", e);
            throw new Json.JsonException(e);
        }
        return mfaMethodCreateRequest;
    }
}

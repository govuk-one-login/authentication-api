package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import io.vavr.control.Either;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.mfa.MfaMethodCreateOrUpdateRequest;
import uk.gov.di.authentication.shared.entity.mfa.MfaMethodData;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.shared.services.mfa.MfaCreateFailureReason;
import uk.gov.di.authentication.shared.services.mfa.MfaMethodsService;
import uk.gov.di.authentication.shared.services.mfa.MfaMigrationFailureReason;

import java.util.Optional;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;

public class MFAMethodsCreateHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final Json objectMapper = SerializationService.getInstance();

    private final ConfigurationService configurationService;
    private final MfaMethodsService mfaMethodsService;
    private final DynamoService dynamoService;
    private static final Logger LOG = LogManager.getLogger(MFAMethodsCreateHandler.class);

    public MFAMethodsCreateHandler() {
        this(ConfigurationService.getInstance());
    }

    public MFAMethodsCreateHandler(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.mfaMethodsService = new MfaMethodsService(configurationService);
        this.dynamoService = new DynamoService(configurationService);
    }

    public MFAMethodsCreateHandler(
            ConfigurationService configurationService,
            MfaMethodsService mfaMethodsService,
            DynamoService dynamoService) {
        this.configurationService = configurationService;
        this.mfaMethodsService = mfaMethodsService;
        this.dynamoService = dynamoService;
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

        var maybeUserProfile = dynamoService.getOptionalUserProfileFromPublicSubject(subject);
        if (maybeUserProfile.isEmpty()) {
            return generateApiGatewayProxyErrorResponse(404, ErrorResponse.ERROR_1056);
        }
        var userProfile = maybeUserProfile.get();

        var maybeMigrationErrorResponse = migrateMfaCredentialsForUserIfRequired(userProfile);
        if (maybeMigrationErrorResponse.isPresent()) return maybeMigrationErrorResponse.get();

        try {
            MfaMethodCreateOrUpdateRequest mfaMethodCreateRequest =
                    readMfaMethodCreateRequest(input);

            LOG.info("Update MFA POST called with: {}", mfaMethodCreateRequest.mfaMethod());

            Either<MfaCreateFailureReason, MfaMethodData> addBackupMfaResult =
                    mfaMethodsService.addBackupMfa(
                            userProfile.getEmail(), mfaMethodCreateRequest.mfaMethod());

            if (addBackupMfaResult.isLeft()) {
                return switch (addBackupMfaResult.getLeft()) {
                    case INVALID_PRIORITY_IDENTIFIER -> generateApiGatewayProxyErrorResponse(
                            400, ErrorResponse.ERROR_1001);
                    case BACKUP_AND_DEFAULT_METHOD_ALREADY_EXIST -> generateApiGatewayProxyErrorResponse(
                            400, ErrorResponse.ERROR_1068);
                    case PHONE_NUMBER_ALREADY_EXISTS -> generateApiGatewayProxyErrorResponse(
                            400, ErrorResponse.ERROR_1069);
                    case AUTH_APP_EXISTS -> generateApiGatewayProxyErrorResponse(
                            400, ErrorResponse.ERROR_1070);
                    case ERROR_RETRIEVING_MFA_METHODS -> generateApiGatewayProxyErrorResponse(
                            500, ErrorResponse.ERROR_1071);
                };
            }

            return generateApiGatewayProxyResponse(200, addBackupMfaResult.get(), true);

        } catch (Json.JsonException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        }
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

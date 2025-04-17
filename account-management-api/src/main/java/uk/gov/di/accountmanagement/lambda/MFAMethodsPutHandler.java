package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.accountmanagement.helpers.PrincipalValidationHelper;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.mfa.MfaMethodCreateOrUpdateRequest;
import uk.gov.di.authentication.shared.helpers.RequestHeaderHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.shared.services.mfa.MFAMethodsService;
import uk.gov.di.authentication.shared.services.mfa.MfaUpdateFailureReason;

import java.util.Map;

import static uk.gov.di.authentication.shared.domain.RequestHeaders.SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateEmptySuccessApiGatewayResponse;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachSessionIdToLogs;

public class MFAMethodsPutHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(MFAMethodsPutHandler.class);
    private final ConfigurationService configurationService;
    private final MFAMethodsService mfaMethodsService;
    private final AuthenticationService authenticationService;

    private final Json objectMapper = SerializationService.getInstance();

    public MFAMethodsPutHandler() {
        this(ConfigurationService.getInstance());
    }

    public MFAMethodsPutHandler(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.mfaMethodsService = new MFAMethodsService(configurationService);
        this.authenticationService = new DynamoService(configurationService);
    }

    public MFAMethodsPutHandler(
            ConfigurationService configurationService,
            MFAMethodsService mfaMethodsService,
            AuthenticationService authenticationService) {
        this.configurationService = configurationService;
        this.mfaMethodsService = mfaMethodsService;
        this.authenticationService = authenticationService;
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
            APIGatewayProxyRequestEvent input, Context context) {

        addSessionIdToLogs(input);

        if (!configurationService.isMfaMethodManagementApiEnabled()) {
            LOG.error(
                    "Request to update MFA method in {} environment but feature is switched off.",
                    configurationService.getEnvironment());
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1063);
        }

        var publicSubjectId = input.getPathParameters().get("publicSubjectId");
        var mfaIdentifier = input.getPathParameters().get("mfaIdentifier");

        if (publicSubjectId.isEmpty()) {
            LOG.error("Request does not include public subject id");
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        }

        if (mfaIdentifier.isEmpty()) {
            LOG.error("Request does not include mfa identifier");
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        }

        var maybeUserProfile =
                authenticationService.getOptionalUserProfileFromPublicSubject(publicSubjectId);
        if (maybeUserProfile.isEmpty()) {
            LOG.error("Unknown public subject ID");
            return generateApiGatewayProxyErrorResponse(404, ErrorResponse.ERROR_1056);
        }
        UserProfile userProfile = maybeUserProfile.get();

        Map<String, Object> authorizerParams = input.getRequestContext().getAuthorizer();
        if (PrincipalValidationHelper.principalIsInvalid(
                userProfile,
                configurationService.getInternalSectorUri(),
                authenticationService,
                authorizerParams)) {
            return generateApiGatewayProxyErrorResponse(401, ErrorResponse.ERROR_1079);
        }

        try {
            var mfaMethodUpdateRequest =
                    objectMapper.readValue(
                            input.getBody(), MfaMethodCreateOrUpdateRequest.class, true);
            var result =
                    mfaMethodsService.updateMfaMethod(
                            userProfile.getEmail(), mfaIdentifier, mfaMethodUpdateRequest);

            if (result.isFailure()) {
                var failureReason = result.getFailure();
                var response = handleUpdateMfaFailureReason(failureReason);
                if (response.getStatusCode() >= 500) {
                    LOG.error("Update failed due to unexpected error {}", failureReason);
                } else if (response.getStatusCode() >= 400 && response.getStatusCode() < 500) {
                    LOG.warn("Update failed due to {}", failureReason);
                } else {
                    LOG.info("No update to mfa method: {}", failureReason);
                }
                return response;
            }

            var successfulUpdate = result.getSuccess();

            return generateApiGatewayProxyResponse(200, successfulUpdate, true);
        } catch (Json.JsonException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        }
    }

    private static APIGatewayProxyResponseEvent handleUpdateMfaFailureReason(
            MfaUpdateFailureReason failureReason) {
        return switch (failureReason) {
            case CANNOT_CHANGE_TYPE_OF_MFA_METHOD -> generateApiGatewayProxyErrorResponse(
                    400, ErrorResponse.ERROR_1072);
            case ATTEMPT_TO_UPDATE_BACKUP_METHOD_PHONE_NUMBER -> generateApiGatewayProxyErrorResponse(
                    400, ErrorResponse.ERROR_1075);
            case ATTEMPT_TO_UPDATE_BACKUP_METHOD_AUTH_APP_CREDENTIAL -> generateApiGatewayProxyErrorResponse(
                    400, ErrorResponse.ERROR_1076);
            case ATTEMPT_TO_UPDATE_BACKUP_WITH_NO_DEFAULT_METHOD -> generateApiGatewayProxyErrorResponse(
                    500, ErrorResponse.ERROR_1077);
            case UNEXPECTED_ERROR -> generateApiGatewayProxyErrorResponse(
                    500, ErrorResponse.ERROR_1071);
            case UNKOWN_MFA_IDENTIFIER -> generateApiGatewayProxyErrorResponse(
                    404, ErrorResponse.ERROR_1065);
            case CANNOT_CHANGE_PRIORITY_OF_DEFAULT_METHOD -> generateApiGatewayProxyErrorResponse(
                    400, ErrorResponse.ERROR_1073);
            case REQUEST_TO_UPDATE_MFA_METHOD_WITH_NO_CHANGE -> generateEmptySuccessApiGatewayResponse();
            case ATTEMPT_TO_UPDATE_PHONE_NUMBER_WITH_BACKUP_NUMBER -> generateApiGatewayProxyErrorResponse(
                    400, ErrorResponse.ERROR_1074);
        };
    }

    private void addSessionIdToLogs(APIGatewayProxyRequestEvent input) {
        Map<String, String> headers = input.getHeaders();
        String sessionId = RequestHeaderHelper.getHeaderValueOrElse(headers, SESSION_ID_HEADER, "");
        attachSessionIdToLogs(sessionId);
    }
}

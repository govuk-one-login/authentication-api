package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.helpers.RequestHeaderHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.mfa.MfaMethodsService;

import java.util.Map;

import static uk.gov.di.authentication.shared.domain.RequestHeaders.SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateEmptySuccessApiGatewayResponse;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachSessionIdToLogs;

public class MFAMethodsDeleteHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(MFAMethodsDeleteHandler.class);
    private final ConfigurationService configurationService;
    private final MfaMethodsService mfaMethodsService;

    public MFAMethodsDeleteHandler() {
        this(ConfigurationService.getInstance());
    }

    public MFAMethodsDeleteHandler(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.mfaMethodsService = new MfaMethodsService(configurationService);
    }

    public MFAMethodsDeleteHandler(
            ConfigurationService configurationService, MfaMethodsService mfaMethodsService) {
        this.configurationService = configurationService;
        this.mfaMethodsService = mfaMethodsService;
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        ThreadContext.clearMap();
        return segmentedFunctionCall(
                "account-management-api::" + getClass().getSimpleName(),
                () -> deleteMFAMethodHandler(input, context));
    }

    public APIGatewayProxyResponseEvent deleteMFAMethodHandler(
            APIGatewayProxyRequestEvent input, Context context) {

        addSessionIdToLogs(input);

        if (!configurationService.isMfaMethodManagementApiEnabled()) {
            LOG.error(
                    "Request to delete MFA method in {} environment but feature is switched off.",
                    configurationService.getEnvironment());
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1063);
        }

        var publicSubjectId = input.getPathParameters().get("publicSubjectId");
        var mfaIdentifier = input.getPathParameters().get("mfaIdentifier");

        if (publicSubjectId.isEmpty()) {
            LOG.error("Request does not include public subject id");
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1056);
        }

        if (mfaIdentifier.isEmpty()) {
            LOG.error("Request does not include mfa identifier");
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1064);
        }

        var deleteResult = mfaMethodsService.deleteMfaMethod(publicSubjectId, mfaIdentifier);

        if (deleteResult.isLeft()) {
            var failureReason = deleteResult.getLeft();
            LOG.warn(
                    "Attempted to delete mfa with identifier {} but failed for reason {}",
                    mfaIdentifier,
                    failureReason.name());
            return switch (failureReason) {
                case CANNOT_DELETE_DEFAULT_METHOD -> generateApiGatewayProxyErrorResponse(
                        409, ErrorResponse.ERROR_1066);
                case CANNOT_DELETE_MFA_METHOD_FOR_NON_MIGRATED_USER -> generateApiGatewayProxyErrorResponse(
                        400, ErrorResponse.ERROR_1067);
                case MFA_METHOD_WITH_IDENTIFIER_DOES_NOT_EXIST -> generateApiGatewayProxyErrorResponse(
                        404, ErrorResponse.ERROR_1065);
                case NO_USER_PROFILE_FOUND_FOR_PUBLIC_SUBJECT_ID -> generateApiGatewayProxyErrorResponse(
                        404, ErrorResponse.ERROR_1056);
            };
        }

        LOG.info("Successfully deleted MFA method {}", mfaIdentifier);

        return generateEmptySuccessApiGatewayResponse();
    }

    private void addSessionIdToLogs(APIGatewayProxyRequestEvent input) {
        Map<String, String> headers = input.getHeaders();
        String sessionId = RequestHeaderHelper.getHeaderValueOrElse(headers, SESSION_ID_HEADER, "");
        attachSessionIdToLogs(sessionId);
    }
}

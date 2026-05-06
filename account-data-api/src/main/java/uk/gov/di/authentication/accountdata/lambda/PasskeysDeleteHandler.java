package uk.gov.di.authentication.accountdata.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.authentication.accountdata.entity.passkey.failurereasons.PasskeysDeleteFailureReason;
import uk.gov.di.authentication.accountdata.services.PasskeysService;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.Objects;

import static uk.gov.di.authentication.accountdata.helpers.SubjectIdAuthorizerHelper.isSubjectIdAuthorized;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateEmptySuccessApiGatewayResponse;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;

public class PasskeysDeleteHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(PasskeysDeleteHandler.class);
    private final ConfigurationService configurationService;
    private final PasskeysService passkeysService;

    public PasskeysDeleteHandler() {
        this(ConfigurationService.getInstance());
    }

    public PasskeysDeleteHandler(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.passkeysService = new PasskeysService(configurationService);
    }

    public PasskeysDeleteHandler(
            ConfigurationService configurationService, PasskeysService passkeysService) {
        this.configurationService = configurationService;
        this.passkeysService = passkeysService;
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        ThreadContext.clearMap();
        return segmentedFunctionCall(
                "account-data-api::" + getClass().getSimpleName(),
                () -> passkeysDeleteHandler(input, context));
    }

    public APIGatewayProxyResponseEvent passkeysDeleteHandler(
            APIGatewayProxyRequestEvent input, Context context) {
        LOG.info("PasskeysDeleteHandler called");

        return validateRequest(input)
                .flatMap(
                        validDeleteParams ->
                                passkeysService.deletePasskey(
                                        validDeleteParams.publicSubjectId,
                                        validDeleteParams.passkeyId))
                .fold(this::mapDeleteFailure, success -> generateEmptySuccessApiGatewayResponse());
    }

    private record ValidDeleteParams(String publicSubjectId, String passkeyId) {}

    private Result<PasskeysDeleteFailureReason, ValidDeleteParams> validateRequest(
            APIGatewayProxyRequestEvent input) {
        var publicSubjectId = input.getPathParameters().get("publicSubjectId");
        var passkeyId = input.getPathParameters().get("passkeyId");

        if (Objects.isNull(publicSubjectId) || publicSubjectId.isEmpty()) {
            return Result.failure(PasskeysDeleteFailureReason.MISSING_SUBJECT_ID);
        }

        if (Objects.isNull(passkeyId) || passkeyId.isEmpty()) {
            return Result.failure(PasskeysDeleteFailureReason.MISSING_PASSKEY_ID);
        }

        if (!isSubjectIdAuthorized(
                input.getPathParameters().get("publicSubjectId"), input.getRequestContext())) {
            return Result.failure(PasskeysDeleteFailureReason.UNAUTHORIZED_REQUEST);
        }

        return Result.success(new ValidDeleteParams(publicSubjectId, passkeyId));
    }

    private APIGatewayProxyResponseEvent mapDeleteFailure(
            PasskeysDeleteFailureReason failureReason) {
        return switch (failureReason) {
            case MISSING_SUBJECT_ID -> generateApiGatewayProxyErrorResponse(
                    400, ErrorResponse.MISSING_SUBJECT_ID);
            case MISSING_PASSKEY_ID -> generateApiGatewayProxyErrorResponse(
                    400, ErrorResponse.MISSING_PASSKEY_ID);
            case UNAUTHORIZED_REQUEST -> generateApiGatewayProxyErrorResponse(
                    401, ErrorResponse.UNAUTHORIZED_REQUEST);
            case PASSKEY_NOT_FOUND -> generateApiGatewayProxyErrorResponse(
                    404, ErrorResponse.PASSKEY_NOT_FOUND);
            case FAILED_TO_DELETE_PASSKEY -> generateApiGatewayProxyErrorResponse(
                    500, ErrorResponse.INTERNAL_SERVER_ERROR);
        };
    }
}

package uk.gov.di.authentication.accountdata.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.authentication.accountdata.entity.password.VerifyPasswordRequest;
import uk.gov.di.authentication.accountdata.entity.password.VerifyPasswordResponse;
import uk.gov.di.authentication.accountdata.entity.password.failurereasons.VerifyPasswordFailureReason;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.serialization.Json;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;

public class VerifyPasswordHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(VerifyPasswordHandler.class);

    public VerifyPasswordHandler() {}

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        ThreadContext.clearMap();
        return segmentedFunctionCall(
                "account-data-api::" + getClass().getSimpleName(),
                () -> verifyPasswordHandler(input, context));
    }

    public APIGatewayProxyResponseEvent verifyPasswordHandler(
            APIGatewayProxyRequestEvent input, Context context) {
        LOG.info("VerifyPasswordHandler called");

        return generateApiResponse(false)
                .fold(
                        failure ->
                                switch (failure) {
                                    case FAILED_TO_SERIALIZE_RESPONSE -> generateApiGatewayProxyErrorResponse(
                                            500, ErrorResponse.INTERNAL_SERVER_ERROR);
                                },
                        success -> success);
    }

    private Result<VerifyPasswordFailureReason, APIGatewayProxyResponseEvent> generateApiResponse(
            boolean verified) {
        try {
            return Result.success(
                    generateApiGatewayProxyResponse(
                            200, new VerifyPasswordResponse(verified), true));
        } catch (Json.JsonException e) {
            LOG.error("Failed to serialize VerifyPasswordResponse", e);
            return Result.failure(VerifyPasswordFailureReason.FAILED_TO_SERIALIZE_RESPONSE);
        }
    }
}

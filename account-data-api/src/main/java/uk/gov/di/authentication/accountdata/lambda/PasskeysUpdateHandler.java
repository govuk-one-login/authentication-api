package uk.gov.di.authentication.accountdata.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.authentication.accountdata.entity.PasskeysUpdateFailureReason;
import uk.gov.di.authentication.accountdata.entity.PasskeysUpdateRequest;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SerializationService;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;

public class PasskeysUpdateHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(PasskeysUpdateHandler.class);
    private final ConfigurationService configurationService;
    protected final SerializationService objectMapper;

    public PasskeysUpdateHandler() {
        this(ConfigurationService.getInstance());
    }

    public PasskeysUpdateHandler(
            ConfigurationService configurationService, SerializationService serializationService) {
        this.configurationService = configurationService;
        this.objectMapper = serializationService;
    }

    public PasskeysUpdateHandler(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.objectMapper = SerializationService.getInstance();
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        ThreadContext.clearMap();
        return segmentedFunctionCall(
                "account-data-api::" + getClass().getSimpleName(),
                () -> passkeysUpdateHandler(input, context));
    }

    public APIGatewayProxyResponseEvent passkeysUpdateHandler(
            APIGatewayProxyRequestEvent input, Context context) {

        LOG.info("PasskeysUpdateHandler called");

        Result<PasskeysUpdateFailureReason, PasskeysUpdateRequest> result =
                validateUpdateRequest(input);

        return result.fold(
                failure ->
                        generateApiGatewayProxyErrorResponse(
                                400, ErrorResponse.UNEXPECTED_ACCOUNT_DATA_API_ERROR),
                passkeyUpdateResult -> generateApiGatewayProxyResponse(204, ""));
    }

    public Result<PasskeysUpdateFailureReason, PasskeysUpdateRequest> validateUpdateRequest(
            APIGatewayProxyRequestEvent input) {
        PasskeysUpdateRequest passkeysUpdateRequest;
        try {
            passkeysUpdateRequest =
                    objectMapper.readValue(input.getBody(), PasskeysUpdateRequest.class, true);

        } catch (Json.JsonException e) {
            return Result.failure(PasskeysUpdateFailureReason.PARSING_PASSKEY_UPDATE_REQUEST_ERROR);
        }

        return Result.success(passkeysUpdateRequest);
    }
}

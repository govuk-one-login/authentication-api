package uk.gov.di.authentication.accountdata.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.authentication.accountdata.entity.PasskeysCreateFailureReason;
import uk.gov.di.authentication.accountdata.entity.PasskeysCreateRequest;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SerializationService;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;

public class PasskeysCreateHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(PasskeysCreateHandler.class);
    private final ConfigurationService configurationService;
    protected final SerializationService objectMapper;

    public PasskeysCreateHandler() {
        this(ConfigurationService.getInstance());
    }

    public PasskeysCreateHandler(
            ConfigurationService configurationService, SerializationService serializationService) {
        this.configurationService = configurationService;
        this.objectMapper = serializationService;
    }

    public PasskeysCreateHandler(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.objectMapper = SerializationService.getInstance();
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        ThreadContext.clearMap();
        return segmentedFunctionCall(
                "account-data-api::" + getClass().getSimpleName(),
                () -> passkeysCreateHandler(input, context));
    }

    public APIGatewayProxyResponseEvent passkeysCreateHandler(
            APIGatewayProxyRequestEvent input, Context context) {

        LOG.info("PasskeysCreateHandler called");

        Result<PasskeysCreateFailureReason, PasskeysCreateRequest> result =
                validateCreateRequest(input);

        return result.fold(
                failure ->
                        generateApiGatewayProxyErrorResponse(
                                500, ErrorResponse.UNEXPECTED_ACCOUNT_DATA_API_ERROR),
                passkeyCreateResult -> generateApiGatewayProxyResponse(201, ""));
    }

    public Result<PasskeysCreateFailureReason, PasskeysCreateRequest> validateCreateRequest(
            APIGatewayProxyRequestEvent input) {
        PasskeysCreateRequest passkeysCreateRequest;
        try {
            passkeysCreateRequest =
                    objectMapper.readValue(input.getBody(), PasskeysCreateRequest.class, true);

        } catch (Json.JsonException e) {
            return Result.failure(PasskeysCreateFailureReason.PARSING_PASSKEY_CREATE_REQUEST_ERROR);
        }

        return Result.success(passkeysCreateRequest);
    }
}

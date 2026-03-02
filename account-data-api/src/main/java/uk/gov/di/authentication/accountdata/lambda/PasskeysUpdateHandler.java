package uk.gov.di.authentication.accountdata.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.authentication.accountdata.entity.passkey.PasskeysUpdateRequest;
import uk.gov.di.authentication.accountdata.entity.passkey.failurereasons.PasskeysUpdateFailureReason;
import uk.gov.di.authentication.accountdata.services.PasskeysService;
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
    private final PasskeysService passkeysService;

    public PasskeysUpdateHandler() {
        this(ConfigurationService.getInstance());
    }

    public PasskeysUpdateHandler(
            ConfigurationService configurationService,
            SerializationService serializationService,
            PasskeysService passkeysService) {
        this.configurationService = configurationService;
        this.objectMapper = serializationService;
        this.passkeysService = passkeysService;
    }

    public PasskeysUpdateHandler(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.objectMapper = SerializationService.getInstance();
        this.passkeysService = new PasskeysService(configurationService);
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

        // TODO add validation
        String publicSubjectId = getPublicSubjectId(input);
        String passkeyId = getPasskeyId(input);

        return validateUpdateRequest(input)
                .flatMap(
                        request ->
                                passkeysService.updatePasskey(
                                        publicSubjectId,
                                        passkeyId,
                                        request.lastUsedAt(),
                                        request.signCount()))
                .fold(
                        this::mapFailureReasonToErrorResponse,
                        result -> generateApiGatewayProxyResponse(204, ""));
    }

    private APIGatewayProxyResponseEvent mapFailureReasonToErrorResponse(
            PasskeysUpdateFailureReason failureReason) {
        LOG.warn("Failed to update passkey for reason: {} ", failureReason.getValue());
        return switch (failureReason) {
            case PARSING_PASSKEY_UPDATE_REQUEST_ERROR -> generateApiGatewayProxyErrorResponse(
                    400, ErrorResponse.INVALID_REQUEST_BODY);
            case PASSKEY_NOT_FOUND -> generateApiGatewayProxyErrorResponse(
                    404, ErrorResponse.PASSKEY_NOT_FOUND);
            case FAILED_TO_UPDATE_PASSKEY -> generateApiGatewayProxyErrorResponse(
                    500, ErrorResponse.INTERNAL_SERVER_ERROR);
        };
    }

    private String getPublicSubjectId(APIGatewayProxyRequestEvent input) {
        return input.getPathParameters().get("publicSubjectId");
    }

    private String getPasskeyId(APIGatewayProxyRequestEvent input) {
        return input.getPathParameters().get("passkeyId");
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

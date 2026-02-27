package uk.gov.di.authentication.accountdata.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.authentication.accountdata.entity.passkey.PasskeysCreateRequest;
import uk.gov.di.authentication.accountdata.entity.passkey.failurereasons.PasskeysCreateHandlerFailureReason;
import uk.gov.di.authentication.accountdata.entity.passkey.failurereasons.PasskeysCreateServiceFailureReason;
import uk.gov.di.authentication.accountdata.services.PasskeysCreateService;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SerializationService;

import static uk.gov.di.authentication.accountdata.entity.passkey.failurereasons.PasskeysCreateHandlerFailureReason.INVALID_AAGUID;
import static uk.gov.di.authentication.accountdata.entity.passkey.failurereasons.PasskeysCreateHandlerFailureReason.INVALID_REQUEST_BODY;
import static uk.gov.di.authentication.accountdata.entity.passkey.failurereasons.PasskeysCreateHandlerFailureReason.MISSING_SUBJECT_ID;
import static uk.gov.di.authentication.accountdata.helpers.PasskeysHelper.isAaguidValid;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;

public class PasskeysCreateHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(PasskeysCreateHandler.class);
    private final ConfigurationService configurationService;
    private final PasskeysCreateService passkeysCreateService;
    private final Json objectMapper = SerializationService.getInstance();

    public PasskeysCreateHandler() {
        this(ConfigurationService.getInstance());
    }

    public PasskeysCreateHandler(
            ConfigurationService configurationService, PasskeysCreateService passkeyService) {
        this.configurationService = configurationService;
        this.passkeysCreateService = passkeyService;
    }

    public PasskeysCreateHandler(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.passkeysCreateService = new PasskeysCreateService(configurationService);
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

        return parseRequest(input)
                .flatMap(this::validateRequest)
                .flatMap(this::createPasskey)
                .fold(
                        failure ->
                                switch (failure) {
                                    case INVALID_REQUEST_BODY -> generateApiGatewayProxyErrorResponse(
                                            400, ErrorResponse.INVALID_REQUEST_BODY);
                                    case MISSING_SUBJECT_ID -> generateApiGatewayProxyErrorResponse(
                                            400, ErrorResponse.MISSING_SUBJECT_ID);
                                    case PASSKEY_EXISTS -> generateApiGatewayProxyErrorResponse(
                                            409, ErrorResponse.PASSKEY_ALREADY_EXISTS);
                                    case INVALID_AAGUID -> generateApiGatewayProxyErrorResponse(
                                            422, ErrorResponse.INVALID_AAGUID);
                                    case FAILED_TO_SAVE_PASSKEY -> generateApiGatewayProxyErrorResponse(
                                            500, ErrorResponse.INTERNAL_SERVER_ERROR);
                                },
                        passkeyCreateResult ->
                                generateApiGatewayProxyResponse(
                                        201, "Passkey created successfully"));
    }

    private Result<PasskeysCreateHandlerFailureReason, PasskeysCreateContext> parseRequest(
            APIGatewayProxyRequestEvent input) {
        PasskeysCreateRequest passkeysCreateRequest;
        try {
            passkeysCreateRequest =
                    objectMapper.readValue(input.getBody(), PasskeysCreateRequest.class, true);
        } catch (Json.JsonException e) {
            return Result.failure(INVALID_REQUEST_BODY);
        }

        var publicSubjectId = input.getPathParameters().get("publicSubjectId");
        if (publicSubjectId == null || publicSubjectId.isEmpty()) {
            LOG.error("Request does not include public subject id");
            return Result.failure(MISSING_SUBJECT_ID);
        }

        return Result.success(new PasskeysCreateContext(publicSubjectId, passkeysCreateRequest));
    }

    private Result<PasskeysCreateHandlerFailureReason, PasskeysCreateContext> validateRequest(
            PasskeysCreateContext context) {
        var passkeysCreateRequest = context.passkeysCreateRequest();

        if (!isAaguidValid(passkeysCreateRequest.aaguid())) {
            return Result.failure(INVALID_AAGUID);
        }

        return Result.success(context);
    }

    private Result<PasskeysCreateHandlerFailureReason, Void> createPasskey(
            PasskeysCreateContext context) {
        var passkeysCreateRequest = context.passkeysCreateRequest();
        var publicSubjectId = context.publicSubjectId();

        Result<PasskeysCreateServiceFailureReason, Void> result =
                passkeysCreateService.createPasskey(passkeysCreateRequest, publicSubjectId);

        return result.fold(
                failure ->
                        switch (failure) {
                            case FAILED_TO_SAVE_PASSKEY -> Result.failure(
                                    PasskeysCreateHandlerFailureReason.FAILED_TO_SAVE_PASSKEY);
                            case PASSKEY_EXISTS -> Result.failure(
                                    PasskeysCreateHandlerFailureReason.PASSKEY_EXISTS);
                        },
                success -> Result.success(null));
    }

    private record PasskeysCreateContext(
            String publicSubjectId, PasskeysCreateRequest passkeysCreateRequest) {}
}

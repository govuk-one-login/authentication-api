package uk.gov.di.authentication.accountdata.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.authentication.accountdata.entity.passkey.Passkey;
import uk.gov.di.authentication.accountdata.entity.passkey.PasskeysRetrieveResponse;
import uk.gov.di.authentication.accountdata.entity.passkey.failurereasons.PasskeysRetrieveHandlerFailureReasons;
import uk.gov.di.authentication.accountdata.entity.passkey.failurereasons.PasskeysRetrieveServiceFailureReason;
import uk.gov.di.authentication.accountdata.services.PasskeysRetrieveService;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.List;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;

public class PasskeysRetrieveHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(PasskeysRetrieveHandler.class);
    private final ConfigurationService configurationService;
    private final PasskeysRetrieveService passkeysRetrieveService;

    public PasskeysRetrieveHandler() {
        this(ConfigurationService.getInstance());
    }

    public PasskeysRetrieveHandler(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.passkeysRetrieveService = new PasskeysRetrieveService(configurationService);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        ThreadContext.clearMap();
        return segmentedFunctionCall(
                "account-data-api::" + getClass().getSimpleName(),
                () -> passkeysRetrieveHandler(input, context));
    }

    public APIGatewayProxyResponseEvent passkeysRetrieveHandler(
            APIGatewayProxyRequestEvent input, Context context) {

        LOG.info("PasskeysRetrieveHandler called");

        return parseRequest(input)
                .flatMap(this::retrievePasskeys)
                .flatMap(this::mapPasskeysListToResponse)
                .flatMap(this::generateApiResponse)
                .fold(
                        failure ->
                                switch (failure) {
                                    case REQUEST_MISSING_PARAMS -> generateApiGatewayProxyErrorResponse(
                                            400, ErrorResponse.REQUEST_MISSING_PARAMS);
                                    case FAILED_TO_GET_PASSKEYS -> generateApiGatewayProxyErrorResponse(
                                            500, ErrorResponse.FAILED_TO_GET_PASSKEYS);
                                    case FAILED_TO_SERIALIZE_RESPONSE -> generateApiGatewayProxyErrorResponse(
                                            500, ErrorResponse.SERIALIZATION_ERROR);
                                },
                        response -> response);
    }

    private Result<PasskeysRetrieveHandlerFailureReasons, String> parseRequest(
            APIGatewayProxyRequestEvent input) {
        var publicSubjectId = input.getPathParameters().get("publicSubjectId");
        if (publicSubjectId == null || publicSubjectId.isEmpty()) {
            LOG.error("Request does not include public subject id");
            return Result.failure(PasskeysRetrieveHandlerFailureReasons.REQUEST_MISSING_PARAMS);
        }

        return Result.success(publicSubjectId);
    }

    private Result<PasskeysRetrieveHandlerFailureReasons, List<Passkey>> retrievePasskeys(
            String publicSubjectId) {
        Result<PasskeysRetrieveServiceFailureReason, List<Passkey>> retrievePasskeysResult =
                passkeysRetrieveService.retrievePasskeys(publicSubjectId);

        return retrievePasskeysResult.fold(
                failure ->
                        switch (failure) {
                            case MISSING_SUBJECT_ID -> Result.failure(
                                    PasskeysRetrieveHandlerFailureReasons.REQUEST_MISSING_PARAMS);
                            case FAILED_TO_GET_PASSKEYS -> Result.failure(
                                    PasskeysRetrieveHandlerFailureReasons.FAILED_TO_GET_PASSKEYS);
                        },
                Result::success);
    }

    private Result<PasskeysRetrieveHandlerFailureReasons, PasskeysRetrieveResponse>
            mapPasskeysListToResponse(List<Passkey> passkeys) {
        var mappedPasskeysResults =
                passkeys.stream()
                        .map(PasskeysRetrieveResponse::from)
                        .map(Result::getSuccess)
                        .toList();

        return Result.success(new PasskeysRetrieveResponse(mappedPasskeysResults));
    }

    private Result<PasskeysRetrieveHandlerFailureReasons, APIGatewayProxyResponseEvent>
            generateApiResponse(PasskeysRetrieveResponse passkeysRetrieveResponse) {
        try {
            return Result.success(
                    generateApiGatewayProxyResponse(200, passkeysRetrieveResponse, true));
        } catch (Json.JsonException e) {
            LOG.error("Failed to serialize JSON");
            return Result.failure(
                    PasskeysRetrieveHandlerFailureReasons.FAILED_TO_SERIALIZE_RESPONSE);
        }
    }
}

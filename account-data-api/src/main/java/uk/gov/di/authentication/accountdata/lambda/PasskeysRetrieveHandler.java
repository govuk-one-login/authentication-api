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
import uk.gov.di.authentication.accountdata.entity.passkey.failurereasons.PasskeysRetrieveFailureReasons;
import uk.gov.di.authentication.accountdata.services.PasskeysService;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.List;

import static uk.gov.di.authentication.accountdata.entity.passkey.failurereasons.PasskeysRetrieveFailureReasons.UNAUTHORIZED_REQUEST;
import static uk.gov.di.authentication.accountdata.helpers.SubjectIdAuthorizerHelper.isSubjectIdAuthorized;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;

public class PasskeysRetrieveHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(PasskeysRetrieveHandler.class);
    private final ConfigurationService configurationService;
    private final PasskeysService passkeysService;

    public PasskeysRetrieveHandler() {
        this(ConfigurationService.getInstance());
    }

    public PasskeysRetrieveHandler(
            ConfigurationService configurationService, PasskeysService passkeysService) {
        this.configurationService = configurationService;
        this.passkeysService = passkeysService;
    }

    public PasskeysRetrieveHandler(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.passkeysService = new PasskeysService(configurationService);
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
                .flatMap(
                        publicSubjectIdFromPath ->
                                validateAuthorizedSubjectId(publicSubjectIdFromPath, input))
                .flatMap(passkeysService::retrievePasskeys)
                .flatMap(this::mapPasskeysListToResponse)
                .flatMap(this::generateApiResponse)
                .fold(
                        failure ->
                                switch (failure) {
                                    case REQUEST_MISSING_PARAMS -> generateApiGatewayProxyErrorResponse(
                                            400, ErrorResponse.REQUEST_MISSING_PARAMS);
                                    case UNAUTHORIZED_REQUEST -> generateApiGatewayProxyErrorResponse(
                                            401, ErrorResponse.UNAUTHORIZED_REQUEST);
                                    case FAILED_TO_GET_PASSKEYS,
                                            FAILED_TO_SERIALIZE_RESPONSE -> generateApiGatewayProxyErrorResponse(
                                            500, ErrorResponse.INTERNAL_SERVER_ERROR);
                                },
                        response -> response);
    }

    private Result<PasskeysRetrieveFailureReasons, String> parseRequest(
            APIGatewayProxyRequestEvent input) {
        var publicSubjectId = input.getPathParameters().get("publicSubjectId");
        if (publicSubjectId == null || publicSubjectId.isEmpty()) {
            LOG.error("Request does not include public subject id");
            return Result.failure(PasskeysRetrieveFailureReasons.REQUEST_MISSING_PARAMS);
        }

        return Result.success(publicSubjectId);
    }

    private Result<PasskeysRetrieveFailureReasons, String> validateAuthorizedSubjectId(
            String publicSubjectId, APIGatewayProxyRequestEvent input) {
        if (isSubjectIdAuthorized(publicSubjectId, input.getRequestContext())) {
            return Result.success(publicSubjectId);
        } else {
            LOG.warn("SubjectId in path parameter does not match Authorizer principalId");
            return Result.failure(UNAUTHORIZED_REQUEST);
        }
    }

    private Result<PasskeysRetrieveFailureReasons, PasskeysRetrieveResponse>
            mapPasskeysListToResponse(List<Passkey> passkeys) {
        var mappedPasskeysResults = passkeys.stream().map(PasskeysRetrieveResponse::from).toList();

        return Result.success(new PasskeysRetrieveResponse(mappedPasskeysResults));
    }

    private Result<PasskeysRetrieveFailureReasons, APIGatewayProxyResponseEvent>
            generateApiResponse(PasskeysRetrieveResponse passkeysRetrieveResponse) {
        try {
            return Result.success(
                    generateApiGatewayProxyResponse(200, passkeysRetrieveResponse, true));
        } catch (Json.JsonException e) {
            LOG.error("Failed to serialize JSON");
            return Result.failure(PasskeysRetrieveFailureReasons.FAILED_TO_SERIALIZE_RESPONSE);
        }
    }
}

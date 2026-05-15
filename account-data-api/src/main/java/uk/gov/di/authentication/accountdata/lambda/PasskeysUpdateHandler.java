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

import java.time.DateTimeException;
import java.time.Instant;

import static uk.gov.di.authentication.accountdata.entity.passkey.failurereasons.PasskeysUpdateFailureReason.UNAUTHORIZED_REQUEST;
import static uk.gov.di.authentication.accountdata.helpers.SubjectIdAuthorizerHelper.isSubjectIdAuthorized;
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

        return parseUpdateRequest(input)
                .flatMap(updateContext -> validateAuthorizedSubjectId(updateContext, input))
                .flatMap(
                        requestContext ->
                                passkeysService.updatePasskey(
                                        requestContext.publicSubjectId,
                                        requestContext.passkeyId,
                                        requestContext.request.lastUsedAt(),
                                        requestContext.request.signCount()))
                .fold(
                        this::mapFailureReasonToErrorResponse,
                        result -> generateApiGatewayProxyResponse(204, ""));
    }

    private Result<PasskeysUpdateFailureReason, PasskeysUpdateContext> parseUpdateRequest(
            APIGatewayProxyRequestEvent input) {
        PasskeysUpdateRequest passkeysUpdateRequest;
        try {
            passkeysUpdateRequest =
                    objectMapper.readValue(input.getBody(), PasskeysUpdateRequest.class, true);
            Instant.parse(passkeysUpdateRequest.lastUsedAt());
        } catch (Json.JsonException e) {
            return Result.failure(PasskeysUpdateFailureReason.PARSING_PASSKEY_UPDATE_REQUEST_ERROR);
        } catch (DateTimeException e) {
            LOG.warn("last used at time is not a valid timestamp");
            return Result.failure(PasskeysUpdateFailureReason.PARSING_PASSKEY_UPDATE_REQUEST_ERROR);
        }

        var publicSubjectId = input.getPathParameters().get("publicSubjectId");

        if (publicSubjectId == null || publicSubjectId.isEmpty()) {
            LOG.error("Request does not include public subject id");
            return Result.failure(PasskeysUpdateFailureReason.MISSING_SUBJECT_ID);
        }
        var passkeyId = input.getPathParameters().get("passkeyId");

        if (passkeyId == null || passkeyId.isEmpty()) {
            LOG.error("Request does not include passkey id");
            return Result.failure(PasskeysUpdateFailureReason.MISSING_PASSKEY_ID);
        }

        return Result.success(
                new PasskeysUpdateContext(publicSubjectId, passkeyId, passkeysUpdateRequest));
    }

    private Result<PasskeysUpdateFailureReason, PasskeysUpdateContext> validateAuthorizedSubjectId(
            PasskeysUpdateContext passkeysUpdateContext, APIGatewayProxyRequestEvent input) {
        if (isSubjectIdAuthorized(
                passkeysUpdateContext.publicSubjectId, input.getRequestContext())) {
            return Result.success(passkeysUpdateContext);
        } else {
            LOG.warn("SubjectId in path parameter does not match Authorizer principalId");
            return Result.failure(UNAUTHORIZED_REQUEST);
        }
    }

    private APIGatewayProxyResponseEvent mapFailureReasonToErrorResponse(
            PasskeysUpdateFailureReason failureReason) {
        LOG.warn("Failed to update passkey for reason: {} ", failureReason.getValue());
        return switch (failureReason) {
            case PARSING_PASSKEY_UPDATE_REQUEST_ERROR ->
                    generateApiGatewayProxyErrorResponse(400, ErrorResponse.INVALID_REQUEST_BODY);
            case MISSING_SUBJECT_ID ->
                    generateApiGatewayProxyErrorResponse(400, ErrorResponse.MISSING_SUBJECT_ID);
            case MISSING_PASSKEY_ID ->
                    generateApiGatewayProxyErrorResponse(400, ErrorResponse.MISSING_PASSKEY_ID);
            case PASSKEY_NOT_FOUND ->
                    generateApiGatewayProxyErrorResponse(404, ErrorResponse.PASSKEY_NOT_FOUND);
            case FAILED_TO_UPDATE_PASSKEY ->
                    generateApiGatewayProxyErrorResponse(500, ErrorResponse.INTERNAL_SERVER_ERROR);
            case UNAUTHORIZED_REQUEST ->
                    generateApiGatewayProxyErrorResponse(401, ErrorResponse.UNAUTHORIZED_REQUEST);
        };
    }

    private record PasskeysUpdateContext(
            String publicSubjectId, String passkeyId, PasskeysUpdateRequest request) {}
}

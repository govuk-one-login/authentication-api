package uk.gov.di.authentication.accountdata.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.authentication.accountdata.entity.passkey.PasskeysCreateFailureReason;
import uk.gov.di.authentication.accountdata.services.PasskeysCreateService;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;

public class PasskeysCreateHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(PasskeysCreateHandler.class);
    private final ConfigurationService configurationService;
    private final PasskeysCreateService passkeysCreateService;

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

        Result<PasskeysCreateFailureReason, Void> result =
                passkeysCreateService.createPasskey(input);

        return result.fold(
                failure ->
                        switch (failure) {
                            case PARSING_PASSKEY_CREATE_REQUEST_ERROR,
                                    FAILED_TO_SAVE_PASSKEY -> generateApiGatewayProxyErrorResponse(
                                    500, ErrorResponse.UNEXPECTED_ACCOUNT_DATA_API_ERROR);
                            case REQUEST_MISSING_PARAMS -> generateApiGatewayProxyErrorResponse(
                                    400, ErrorResponse.REQUEST_MISSING_PARAMS);
                            case PASSKEY_EXISTS -> generateApiGatewayProxyErrorResponse(
                                    409, ErrorResponse.PASSKEY_ALREADY_EXISTS);
                            case INVALID_AAGUID -> generateApiGatewayProxyErrorResponse(
                                    422, ErrorResponse.INVALID_AAGUID);
                            case INVALID_CREDENTIAL -> generateApiGatewayProxyErrorResponse(
                                    422, ErrorResponse.INVALID_CREDENTIAL);
                        },
                passkeyCreateResult -> generateApiGatewayProxyResponse(201, ""));
    }
}

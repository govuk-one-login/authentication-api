package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.authentication.entity.MfaMethodCreateRequest;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.MfaDetail;
import uk.gov.di.authentication.shared.entity.MfaMethodData;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SerializationService;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.authentication.shared.services.DynamoMfaMethodsService.HARDCODED_APP_MFA_ID;

public class MFAMethodsCreateHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final Json objectMapper = SerializationService.getInstance();

    private final ConfigurationService configurationService;
    private static final Logger LOG = LogManager.getLogger(MFAMethodsCreateHandler.class);

    public MFAMethodsCreateHandler() {
        this(ConfigurationService.getInstance());
    }

    public MFAMethodsCreateHandler(ConfigurationService configurationService) {
        this.configurationService = configurationService;
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        ThreadContext.clearMap();
        return segmentedFunctionCall(
                "account-management-api::" + getClass().getSimpleName(),
                () -> mfaMethodsHandler(input, context));
    }

    public APIGatewayProxyResponseEvent mfaMethodsHandler(
            APIGatewayProxyRequestEvent input, Context context) {
        if (!configurationService.isMfaMethodManagementApiEnabled()) {
            LOG.error(
                    "Request to create MFA method in {} environment but feature is switched off.",
                    configurationService.getEnvironment());
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1063);
        }

        var subject = input.getPathParameters().get("publicSubjectId");
        if (subject == null) {
            LOG.error("Subject missing from request prevents request being handled.");
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        }

        try {
            MfaMethodCreateRequest mfaMethodCreateRequest = readMfaMethodCreateRequest(input);
            MfaDetail mfaMethod = mfaMethodCreateRequest.mfaMethod().method();
            PriorityIdentifier priorityIdentifier =
                    mfaMethodCreateRequest.mfaMethod().priorityIdentifier();

            LOG.info("Update MFA POST called with: {}", mfaMethodCreateRequest.mfaMethod());
            return generateApiGatewayProxyResponse(
                    200,
                    new MfaMethodData(HARDCODED_APP_MFA_ID, priorityIdentifier, true, mfaMethod),
                    true);

        } catch (Json.JsonException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        }
    }

    private MfaMethodCreateRequest readMfaMethodCreateRequest(APIGatewayProxyRequestEvent input)
            throws Json.JsonException {
        MfaMethodCreateRequest mfaMethodCreateRequest;
        try {
            mfaMethodCreateRequest =
                    segmentedFunctionCall(
                            "SerializationService::GSON::fromJson",
                            () ->
                                    objectMapper.readValue(
                                            input.getBody(), MfaMethodCreateRequest.class));

        } catch (RuntimeException e) {
            LOG.error("Error during JSON deserialization", e);
            throw new Json.JsonException(e);
        }
        return mfaMethodCreateRequest;
    }
}

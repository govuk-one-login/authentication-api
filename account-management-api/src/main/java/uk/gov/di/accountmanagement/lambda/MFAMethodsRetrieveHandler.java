package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.helpers.RequestHeaderHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoMfaMethodsService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.MfaMethodsService;
import uk.gov.di.authentication.shared.services.SerializationService;

import java.util.List;
import java.util.Map;

import static uk.gov.di.authentication.shared.domain.RequestHeaders.SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachSessionIdToLogs;

public class MFAMethodsRetrieveHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private final ConfigurationService configurationService;
    private final DynamoService dynamoService;
    private final MfaMethodsService mfaMethodsService;

    private static final String PRODUCTION = "production";
    private static final String INTEGRATION = "integration";

    private static final Logger LOG = LogManager.getLogger(MFAMethodsRetrieveHandler.class);

    public MFAMethodsRetrieveHandler() {
        this(ConfigurationService.getInstance());
    }

    public MFAMethodsRetrieveHandler(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.dynamoService = new DynamoService(configurationService);
        this.mfaMethodsService = new DynamoMfaMethodsService(configurationService);
    }

    public MFAMethodsRetrieveHandler(
            ConfigurationService configurationService,
            DynamoService dynamoService,
            MfaMethodsService mfaMethodsService) {
        this.configurationService = configurationService;
        this.dynamoService = dynamoService;
        this.mfaMethodsService = mfaMethodsService;
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        ThreadContext.clearMap();
        return segmentedFunctionCall(
                "account-management-api::" + getClass().getSimpleName(),
                () -> getMFAMethodsHandler(input, context));
    }

    public APIGatewayProxyResponseEvent getMFAMethodsHandler(
            APIGatewayProxyRequestEvent input, Context context) {

        addSessionIdToLogs(input);

        var disabledEnvironments = List.of(PRODUCTION, INTEGRATION);
        if (disabledEnvironments.contains(configurationService.getEnvironment())) {
            LOG.error(
                    "Request to create MFA method in {} environment but feature is switched off.",
                    configurationService.getEnvironment());
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1063);
        }

        var publicSubjectId = input.getPathParameters().get("publicSubjectId");

        if (publicSubjectId.isEmpty()) {
            LOG.error("Request does not include public subject id");
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1056);
        }

        var maybeUserProfile =
                dynamoService.getOptionalUserProfileFromPublicSubject(publicSubjectId);

        if (maybeUserProfile.isEmpty()) {
            LOG.error("Unknown public subject ID");
            return generateApiGatewayProxyErrorResponse(404, ErrorResponse.ERROR_1056);
        }

        var retrievedMethods = mfaMethodsService.getMfaMethods(maybeUserProfile.get().getEmail());

        var serialisationService = SerializationService.getInstance();
        var response = serialisationService.writeValueAsStringCamelCase(retrievedMethods);

        return generateApiGatewayProxyResponse(200, response);
    }

    private void addSessionIdToLogs(APIGatewayProxyRequestEvent input) {
        Map<String, String> headers = input.getHeaders();
        String sessionId = RequestHeaderHelper.getHeaderValueOrElse(headers, SESSION_ID_HEADER, "");
        attachSessionIdToLogs(sessionId);
    }
}

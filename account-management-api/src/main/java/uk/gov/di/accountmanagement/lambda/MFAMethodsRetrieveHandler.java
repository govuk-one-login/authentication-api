package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.accountmanagement.helpers.PrincipalValidationHelper;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.RequestHeaderHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.shared.services.mfa.MfaMethodsService;

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

    private static final Logger LOG = LogManager.getLogger(MFAMethodsRetrieveHandler.class);

    public MFAMethodsRetrieveHandler() {
        this(ConfigurationService.getInstance());
    }

    public MFAMethodsRetrieveHandler(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.dynamoService = new DynamoService(configurationService);
        this.mfaMethodsService = new MfaMethodsService(configurationService);
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

        if (!configurationService.isMfaMethodManagementApiEnabled()) {
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
        UserProfile userProfile = maybeUserProfile.get();

        Map<String, Object> authorizerParams = input.getRequestContext().getAuthorizer();
        if (PrincipalValidationHelper.principalIsInvalid(
                userProfile,
                configurationService.getInternalSectorUri(),
                dynamoService,
                authorizerParams)) {
            return generateApiGatewayProxyErrorResponse(401, ErrorResponse.ERROR_1079);
        }

        var retrieveResult = mfaMethodsService.getMfaMethods(maybeUserProfile.get().getEmail());

        if (retrieveResult.isLeft()) {
            return switch (retrieveResult.getLeft()) {
                case ERROR_CONVERTING_MFA_METHOD_TO_MFA_METHOD_DATA -> generateApiGatewayProxyErrorResponse(
                        500, ErrorResponse.ERROR_1064);
                case UNEXPECTED_ERROR_CREATING_MFA_IDENTIFIER_FOR_NON_MIGRATED_AUTH_APP -> generateApiGatewayProxyErrorResponse(
                        500, ErrorResponse.ERROR_1078);
            };
        }
        var retrievedMethods = retrieveResult.get();

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

package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.accountmanagement.entity.MfaMethodCreateRequest;
import uk.gov.di.accountmanagement.entity.MfaMethodCreateSuccessResponse;
import uk.gov.di.authentication.shared.entity.AuthAppMfaData;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.MFAMethodType;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.SerializationService;

import java.util.List;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;

public class CreateBackupMFAMethod
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final String PRODUCTION = "production";
    private static final String INTEGRATION = "integration";

    private final Json objectMapper = SerializationService.getInstance();

    private final ConfigurationService configurationService;
    private final DynamoService dynamoService;
    private static final Logger LOG = LogManager.getLogger(CreateBackupMFAMethod.class);

    public CreateBackupMFAMethod() {
        this(ConfigurationService.getInstance());
    }

    public CreateBackupMFAMethod(
            ConfigurationService configurationService, DynamoService dynamoService) {
        this.configurationService = configurationService;
        this.dynamoService = dynamoService;
    }

    public CreateBackupMFAMethod(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.dynamoService = new DynamoService(configurationService);
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
        var disabledEnvironments = List.of(PRODUCTION, INTEGRATION);
        if (disabledEnvironments.contains(configurationService.getEnvironment())) {
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

        String userEmail;
        try {
            userEmail = dynamoService.getUserProfileFromPublicSubject(subject).getEmail();
        } catch (RuntimeException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        }

        try {
            MfaMethodCreateRequest mfaMethodCreateRequest =
                    objectMapper.readValue(input.getBody(), MfaMethodCreateRequest.class);

            MFAMethodType newMfaMethodType =
                    mfaMethodCreateRequest.mfaMethod().method().mfaMethodType();
            if (newMfaMethodType.equals(MFAMethodType.AUTH_APP)) {
                dynamoService.addMFAMethodSupportingMultiple(
                        userEmail,
                        new AuthAppMfaData(
                                mfaMethodCreateRequest.mfaMethod().method().credential(),
                                true,
                                true,
                                PriorityIdentifier.BACKUP,
                                2
                                //                              TODO: need to make mfaIdentifier
                                // increment based on already existing mfaIdentifiers
                                ));
            } else {
                return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
            }

            LOG.info("Update MFA POST called with: {}", mfaMethodCreateRequest.mfaMethod());
            return generateApiGatewayProxyResponse(200, new MfaMethodCreateSuccessResponse(2, PriorityIdentifier.BACKUP, new MfaMethodCreateSuccessResponse.Method(MFAMethodType.AUTH_APP, )));
        } catch (Json.JsonException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        }
    }
}

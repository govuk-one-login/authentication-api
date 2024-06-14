package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.frontendapi.entity.CheckEmailFraudBlockRequest;
import uk.gov.di.authentication.frontendapi.entity.CheckEmailFraudBlockResponse;
import uk.gov.di.authentication.shared.entity.EmailCheckResultStatus;
import uk.gov.di.authentication.shared.lambda.BaseFrontendHandler;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoEmailCheckResultService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.state.UserContext;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;

public class CheckEmailFraudBlockHandler extends BaseFrontendHandler<CheckEmailFraudBlockRequest> {

    private static final Logger LOG = LogManager.getLogger(CheckEmailFraudBlockRequest.class);

    private final AuditService auditService;
    private final DynamoEmailCheckResultService dynamoEmailCheckResultService;

    protected CheckEmailFraudBlockHandler(
            ConfigurationService configurationService,
            SessionService sessionService,
            ClientSessionService clientSessionService,
            ClientService clientService,
            AuthenticationService authenticationService,
            DynamoEmailCheckResultService dynamoEmailCheckResultService,
            AuditService auditService) {
        super(
                CheckEmailFraudBlockRequest.class,
                configurationService,
                sessionService,
                clientSessionService,
                clientService,
                authenticationService);
        this.dynamoEmailCheckResultService = dynamoEmailCheckResultService;
        this.auditService = auditService;
    }

    public CheckEmailFraudBlockHandler(ConfigurationService configurationService) {
        super(CheckEmailFraudBlockRequest.class, configurationService);
        this.dynamoEmailCheckResultService =
                new DynamoEmailCheckResultService(configurationService);
        this.auditService = new AuditService(configurationService);
    }

    public CheckEmailFraudBlockHandler() {
        this(ConfigurationService.getInstance());
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return super.handleRequest(input, context);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequestWithUserContext(
            APIGatewayProxyRequestEvent input,
            Context context,
            CheckEmailFraudBlockRequest request,
            UserContext userContext) {
        try {
            LOG.info("Request received to CheckEmailFraudBlockHandler");
            LOG.info("Checking if block is present");

            var emailCheckResult =
                    dynamoEmailCheckResultService.getEmailCheckStore(request.getEmail());

            if (emailCheckResult.isPresent()) {
                var checkEmailFraudBlockResponse =
                        new CheckEmailFraudBlockResponse(
                                request.getEmail(), emailCheckResult.get().getStatus().getValue());
                return generateApiGatewayProxyResponse(200, checkEmailFraudBlockResponse);
            }
            return generateApiGatewayProxyResponse(
                    200,
                    new CheckEmailFraudBlockResponse(
                            request.getEmail(), EmailCheckResultStatus.PENDING.getValue()));
        } catch (Json.JsonException e) {
            LOG.error("Unable to serialize check email fraud block response", e);
            throw new RuntimeException(e);
        }
    }
}

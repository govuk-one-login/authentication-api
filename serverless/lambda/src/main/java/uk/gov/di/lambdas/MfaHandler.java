package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import uk.gov.di.entity.BaseAPIResponse;
import uk.gov.di.entity.ErrorResponse;
import uk.gov.di.entity.NotifyRequest;
import uk.gov.di.entity.Session;
import uk.gov.di.entity.UserWithEmailRequest;
import uk.gov.di.services.AuthenticationService;
import uk.gov.di.services.AwsSqsClient;
import uk.gov.di.services.CodeGeneratorService;
import uk.gov.di.services.CodeStorageService;
import uk.gov.di.services.ConfigurationService;
import uk.gov.di.services.DynamoService;
import uk.gov.di.services.RedisConnectionService;
import uk.gov.di.services.SessionService;

import static uk.gov.di.entity.NotificationType.MFA_SMS;
import static uk.gov.di.entity.SessionState.MFA_SMS_CODE_SENT;
import static uk.gov.di.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;

public class MfaHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final ConfigurationService configurationService;
    private final SessionService sessionService;
    private final CodeGeneratorService codeGeneratorService;
    private final CodeStorageService codeStorageService;
    private final AuthenticationService authenticationService;
    private final AwsSqsClient sqsClient;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public MfaHandler(
            ConfigurationService configurationService,
            SessionService sessionService,
            CodeGeneratorService codeGeneratorService,
            CodeStorageService codeStorageService,
            AuthenticationService authenticationService,
            AwsSqsClient sqsClient) {
        this.configurationService = configurationService;
        this.sessionService = sessionService;
        this.codeGeneratorService = codeGeneratorService;
        this.codeStorageService = codeStorageService;
        this.authenticationService = authenticationService;
        this.sqsClient = sqsClient;
    }

    public MfaHandler() {
        this.configurationService = new ConfigurationService();
        this.sessionService = new SessionService(configurationService);
        this.codeGeneratorService = new CodeGeneratorService();
        this.codeStorageService =
                new CodeStorageService(new RedisConnectionService(configurationService));
        this.authenticationService =
                new DynamoService(
                        configurationService.getAwsRegion(),
                        configurationService.getEnvironment(),
                        configurationService.getDynamoEndpointUri());
        this.sqsClient =
                new AwsSqsClient(
                        configurationService.getAwsRegion(),
                        configurationService.getEmailQueueUri(),
                        configurationService.getSqsEndpointUri());
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        Session session =
                sessionService.getSessionFromRequestHeaders(input.getHeaders()).orElse(null);
        if (session == null) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1000);
        }
        try {
            UserWithEmailRequest userWithEmailRequest =
                    objectMapper.readValue(input.getBody(), UserWithEmailRequest.class);
            if (!session.validateSession(userWithEmailRequest.getEmail())) {
                return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1000);
            }
            String phoneNumber =
                    authenticationService
                            .getPhoneNumber(userWithEmailRequest.getEmail())
                            .orElse(null);

            if (phoneNumber == null) {
                return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1014);
            }
            String code = codeGeneratorService.sixDigitCode();
            codeStorageService.saveOtpCode(
                    userWithEmailRequest.getEmail(),
                    code,
                    configurationService.getCodeExpiry(),
                    MFA_SMS);
            sessionService.save(session.setState(MFA_SMS_CODE_SENT));
            NotifyRequest notifyRequest = new NotifyRequest(phoneNumber, MFA_SMS, code);
            sqsClient.send(objectMapper.writeValueAsString(notifyRequest));
            return generateApiGatewayProxyResponse(200, new BaseAPIResponse(session.getState()));
        } catch (JsonProcessingException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        }
    }
}

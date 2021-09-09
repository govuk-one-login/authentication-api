package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.authentication.frontendapi.entity.UserWithEmailRequest;
import uk.gov.di.authentication.frontendapi.services.AwsSqsClient;
import uk.gov.di.authentication.shared.entity.BaseAPIResponse;
import uk.gov.di.authentication.shared.entity.NotifyRequest;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.helpers.StateMachine;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.CodeGeneratorService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.SessionService;

import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1000;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1001;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1014;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1017;
import static uk.gov.di.authentication.shared.entity.NotificationType.MFA_SMS;
import static uk.gov.di.authentication.shared.entity.SessionState.MFA_SMS_CODE_SENT;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;

public class MfaHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER = LoggerFactory.getLogger(MfaHandler.class);

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
            LOGGER.error("Session cannot be found");
            return generateApiGatewayProxyErrorResponse(400, ERROR_1000);
        } else {
            LOGGER.info("MfaHandler processing request for session {}", session.getSessionId());
        }

        try {
            StateMachine.validateStateTransition(session, MFA_SMS_CODE_SENT);

            UserWithEmailRequest userWithEmailRequest =
                    objectMapper.readValue(input.getBody(), UserWithEmailRequest.class);
            if (!session.validateSession(userWithEmailRequest.getEmail())) {
                LOGGER.error("Email in session does not match Email in Request");
                return generateApiGatewayProxyErrorResponse(400, ERROR_1000);
            }
            String phoneNumber =
                    authenticationService
                            .getPhoneNumber(userWithEmailRequest.getEmail())
                            .orElse(null);

            if (phoneNumber == null) {
                LOGGER.error("PhoneNumber is null");
                return generateApiGatewayProxyErrorResponse(400, ERROR_1014);
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

            LOGGER.info(
                    "MfaHandler successfully processed request for session {}",
                    session.getSessionId());

            return generateApiGatewayProxyResponse(200, new BaseAPIResponse(session.getState()));
        } catch (JsonProcessingException e) {
            LOGGER.error("Request is missing parameters. Request Body: {}", input.getBody());
            return generateApiGatewayProxyErrorResponse(400, ERROR_1001);
        } catch (StateMachine.InvalidStateTransitionException e) {
            LOGGER.error("Invalid transition in user journey");
            return generateApiGatewayProxyErrorResponse(400, ERROR_1017);
        }
    }
}

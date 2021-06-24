package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.LambdaLogger;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import software.amazon.awssdk.core.exception.SdkClientException;
import uk.gov.di.entity.NotifyRequest;
import uk.gov.di.entity.SendNotificationRequest;
import uk.gov.di.entity.Session;
import uk.gov.di.services.AwsSqsClient;
import uk.gov.di.services.ConfigurationService;
import uk.gov.di.services.SessionService;
import uk.gov.di.services.ValidationService;
import uk.gov.di.validation.EmailValidation;

import java.util.Optional;
import java.util.Set;

import static uk.gov.di.Messages.ERROR_INVALID_NOTIFICATION_TYPE;
import static uk.gov.di.Messages.ERROR_INVALID_SESSION_ID;
import static uk.gov.di.entity.SessionState.VERIFY_EMAIL_CODE_SENT;
import static uk.gov.di.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;

public class SendNotificationHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final ConfigurationService configurationService;
    private final ValidationService validationService;
    private final AwsSqsClient sqsClient;
    private final SessionService sessionService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public SendNotificationHandler(
            ConfigurationService configurationService,
            ValidationService validationService,
            AwsSqsClient sqsClient,
            SessionService sessionService) {
        this.configurationService = configurationService;
        this.validationService = validationService;
        this.sqsClient = sqsClient;
        this.sessionService = sessionService;
    }

    public SendNotificationHandler() {
        this.configurationService = new ConfigurationService();
        this.sqsClient =
                new AwsSqsClient(
                        configurationService.getAwsRegion(),
                        configurationService.getEmailQueueUri(),
                        configurationService.getSqsEndpointUri());
        this.validationService = new ValidationService();
        sessionService = new SessionService(configurationService);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        LambdaLogger logger = context.getLogger();

        Optional<Session> session = sessionService.getSessionFromRequestHeaders(input.getHeaders());
        if (session.isEmpty()) {
            return generateApiGatewayProxyResponse(400, ERROR_INVALID_SESSION_ID);
        }
        try {
            SendNotificationRequest sendNotificationRequest =
                    objectMapper.readValue(input.getBody(), SendNotificationRequest.class);
            switch (sendNotificationRequest.getNotificationType()) {
                case VERIFY_EMAIL:
                    Set<EmailValidation> emailErrors =
                            validationService.validateEmailAddress(
                                    sendNotificationRequest.getEmail());
                    if (!emailErrors.isEmpty()) {
                        return generateApiGatewayProxyResponse(400, emailErrors.toString());
                    }
                    if (!session.get().validateSession(sendNotificationRequest.getEmail())) {
                        return generateApiGatewayProxyResponse(400, ERROR_INVALID_SESSION_ID);
                    }
                    NotifyRequest notifyRequest =
                            new NotifyRequest(
                                    sendNotificationRequest.getEmail(),
                                    sendNotificationRequest.getNotificationType());
                    sessionService.save(session.get().setState(VERIFY_EMAIL_CODE_SENT));
                    sqsClient.send(serialiseRequest(notifyRequest));
                    return generateApiGatewayProxyResponse(200, "OK");
            }
            return generateApiGatewayProxyResponse(400, ERROR_INVALID_NOTIFICATION_TYPE);
        } catch (SdkClientException ex) {
            logger.log("Error sending message to queue: " + ex.getMessage());
            return generateApiGatewayProxyResponse(500, "Error sending message to queue");
        } catch (JsonProcessingException e) {
            logger.log("Error parsing request: " + e.getMessage());
            return generateApiGatewayProxyResponse(400, "Request is missing parameters");
        }
    }

    private String serialiseRequest(Object request) throws JsonProcessingException {
        return objectMapper.writeValueAsString(request);
    }
}

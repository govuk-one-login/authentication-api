package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.core.exception.SdkClientException;
import uk.gov.di.authentication.frontendapi.entity.NotifyRequest;
import uk.gov.di.authentication.frontendapi.entity.SendNotificationRequest;
import uk.gov.di.authentication.frontendapi.services.AwsSqsClient;
import uk.gov.di.authentication.shared.entity.BaseAPIResponse;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.SessionState;
import uk.gov.di.authentication.shared.helpers.StateMachine;
import uk.gov.di.authentication.shared.services.CodeGeneratorService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.services.ValidationService;

import java.util.Optional;

import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1001;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1002;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1011;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1017;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;

public class SendNotificationHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER = LoggerFactory.getLogger(SendNotificationHandler.class);

    private final ConfigurationService configurationService;
    private final ValidationService validationService;
    private final AwsSqsClient sqsClient;
    private final SessionService sessionService;
    private final CodeGeneratorService codeGeneratorService;
    private final CodeStorageService codeStorageService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public SendNotificationHandler(
            ConfigurationService configurationService,
            ValidationService validationService,
            AwsSqsClient sqsClient,
            SessionService sessionService,
            CodeGeneratorService codeGeneratorService,
            CodeStorageService codeStorageService) {
        this.configurationService = configurationService;
        this.validationService = validationService;
        this.sqsClient = sqsClient;
        this.sessionService = sessionService;
        this.codeGeneratorService = codeGeneratorService;
        this.codeStorageService = codeStorageService;
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
        this.codeGeneratorService = new CodeGeneratorService();
        this.codeStorageService =
                new CodeStorageService(new RedisConnectionService(configurationService));
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        Optional<Session> session = sessionService.getSessionFromRequestHeaders(input.getHeaders());
        if (session.isEmpty()) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1000);
        }
        try {
            SendNotificationRequest sendNotificationRequest =
                    objectMapper.readValue(input.getBody(), SendNotificationRequest.class);
            if (!session.get().validateSession(sendNotificationRequest.getEmail())) {
                return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1000);
            }
            switch (sendNotificationRequest.getNotificationType()) {
                case VERIFY_EMAIL:
                    StateMachine.validateStateTransition(
                            session.get(), SessionState.VERIFY_EMAIL_CODE_SENT);

                    Optional<ErrorResponse> emailErrorResponse =
                            validationService.validateEmailAddress(
                                    sendNotificationRequest.getEmail());
                    if (emailErrorResponse.isPresent()) {
                        return generateApiGatewayProxyErrorResponse(400, emailErrorResponse.get());
                    }
                    return handleNotificationRequest(
                            sendNotificationRequest.getEmail(),
                            sendNotificationRequest.getNotificationType(),
                            session.get());
                case VERIFY_PHONE_NUMBER:
                    StateMachine.validateStateTransition(
                            session.get(), SessionState.VERIFY_PHONE_NUMBER_CODE_SENT);

                    if (sendNotificationRequest.getPhoneNumber() == null) {
                        return generateApiGatewayProxyResponse(400, ERROR_1011);
                    }
                    String phoneNumber =
                            removeWhitespaceFromPhoneNumber(
                                    sendNotificationRequest.getPhoneNumber());
                    Optional<ErrorResponse> errorResponse =
                            validationService.validatePhoneNumber(phoneNumber);
                    if (errorResponse.isPresent()) {
                        return generateApiGatewayProxyErrorResponse(400, errorResponse.get());
                    }
                    return handleNotificationRequest(
                            phoneNumber,
                            sendNotificationRequest.getNotificationType(),
                            session.get());
            }
            return generateApiGatewayProxyErrorResponse(400, ERROR_1002);
        } catch (SdkClientException ex) {
            LOGGER.error("Error sending message to queue", ex);
            return generateApiGatewayProxyResponse(500, "Error sending message to queue");
        } catch (JsonProcessingException e) {
            LOGGER.error("Error parsing request", e);
            return generateApiGatewayProxyErrorResponse(400, ERROR_1001);
        } catch (StateMachine.InvalidStateTransitionException e) {
            return generateApiGatewayProxyErrorResponse(400, ERROR_1017);
        }
    }

    private String removeWhitespaceFromPhoneNumber(String phoneNumber) {
        return phoneNumber.replaceAll("\\s+", "");
    }

    private APIGatewayProxyResponseEvent handleNotificationRequest(
            String destination, NotificationType notificationType, Session session)
            throws JsonProcessingException {

        String code = codeGeneratorService.sixDigitCode();
        NotifyRequest notifyRequest = new NotifyRequest(destination, notificationType, code);

        switch (notificationType) {
            case VERIFY_EMAIL:
                codeStorageService.saveOtpCode(
                        destination,
                        code,
                        configurationService.getCodeExpiry(),
                        NotificationType.VERIFY_EMAIL);
                sessionService.save(session.setState(SessionState.VERIFY_EMAIL_CODE_SENT));
                break;
            case VERIFY_PHONE_NUMBER:
                codeStorageService.saveOtpCode(
                        session.getEmailAddress(),
                        code,
                        configurationService.getCodeExpiry(),
                        NotificationType.VERIFY_PHONE_NUMBER);
                sessionService.save(
                        session.setState(SessionState.VERIFY_PHONE_NUMBER_CODE_SENT)
                                .resetRetryCount());
                break;
        }
        sqsClient.send(serialiseRequest(notifyRequest));
        return generateApiGatewayProxyResponse(200, new BaseAPIResponse(session.getState()));
    }

    private String serialiseRequest(Object request) throws JsonProcessingException {
        return objectMapper.writeValueAsString(request);
    }
}

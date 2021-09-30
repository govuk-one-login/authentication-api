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
import uk.gov.di.authentication.frontendapi.entity.SendNotificationRequest;
import uk.gov.di.authentication.frontendapi.services.AwsSqsClient;
import uk.gov.di.authentication.shared.entity.BaseAPIResponse;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.entity.NotifyRequest;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.SessionAction;
import uk.gov.di.authentication.shared.entity.SessionState;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.CodeGeneratorService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.services.ValidationService;
import uk.gov.di.authentication.shared.state.StateMachine;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.Optional;

import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1001;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1002;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1011;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1017;
import static uk.gov.di.authentication.shared.entity.SessionAction.SYSTEM_HAS_SENT_EMAIL_VERIFICATION_CODE;
import static uk.gov.di.authentication.shared.entity.SessionAction.SYSTEM_HAS_SENT_PHONE_VERIFICATION_CODE;
import static uk.gov.di.authentication.shared.entity.SessionAction.SYSTEM_HAS_SENT_TOO_MANY_EMAIL_VERIFICATION_CODES;
import static uk.gov.di.authentication.shared.entity.SessionAction.SYSTEM_HAS_SENT_TOO_MANY_PHONE_VERIFICATION_CODES;
import static uk.gov.di.authentication.shared.entity.SessionAction.SYSTEM_IS_BLOCKED_FROM_SENDING_ANY_EMAIL_VERIFICATION_CODES;
import static uk.gov.di.authentication.shared.entity.SessionAction.SYSTEM_IS_BLOCKED_FROM_SENDING_ANY_PHONE_VERIFICATION_CODES;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.state.StateMachine.userJourneyStateMachine;

public class SendNotificationHandler extends BaseFrontendHandler<SendNotificationRequest>
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER = LoggerFactory.getLogger(SendNotificationHandler.class);

    private final ValidationService validationService;
    private final AwsSqsClient sqsClient;
    private final CodeGeneratorService codeGeneratorService;
    private final CodeStorageService codeStorageService;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final StateMachine<SessionState, SessionAction, UserContext> stateMachine =
            userJourneyStateMachine();

    public SendNotificationHandler(
            ConfigurationService configurationService,
            SessionService sessionService,
            ClientSessionService clientSessionService,
            ClientService clientService,
            AuthenticationService authenticationService,
            ValidationService validationService,
            AwsSqsClient sqsClient,
            CodeGeneratorService codeGeneratorService,
            CodeStorageService codeStorageService) {
        super(
                SendNotificationRequest.class,
                configurationService,
                sessionService,
                clientSessionService,
                clientService,
                authenticationService);
        this.validationService = validationService;
        this.sqsClient = sqsClient;
        this.codeGeneratorService = codeGeneratorService;
        this.codeStorageService = codeStorageService;
    }

    public SendNotificationHandler() {
        super(SendNotificationRequest.class, ConfigurationService.getInstance());
        this.sqsClient =
                new AwsSqsClient(
                        configurationService.getAwsRegion(),
                        configurationService.getEmailQueueUri(),
                        configurationService.getSqsEndpointUri());
        this.validationService = new ValidationService();
        this.codeGeneratorService = new CodeGeneratorService();
        this.codeStorageService =
                new CodeStorageService(new RedisConnectionService(configurationService));
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequestWithUserContext(
            APIGatewayProxyRequestEvent input, Context context, SendNotificationRequest request, UserContext userContext) {
        try {
            if (!userContext.getSession()
                    .validateSession(request.getEmail())) {
                LOGGER.info(
                        "Invalid session. Email {}",
                        request.getEmail());
                return generateApiGatewayProxyErrorResponse(
                        400, ErrorResponse.ERROR_1000);
            }
            boolean codeRequestValid =
                    isCodeRequestAttemptValid(
                            request.getEmail(),
                            userContext.getSession(),
                            request.getNotificationType(), userContext);
            if (!codeRequestValid) {
                return generateApiGatewayProxyResponse(
                        400, new BaseAPIResponse(userContext.getSession().getState()));
            }
            SessionState nextState;
            switch (request.getNotificationType()) {
                case VERIFY_EMAIL:
                    nextState =
                            stateMachine.transition(
                                    userContext.getSession().getState(),
                                    SYSTEM_HAS_SENT_EMAIL_VERIFICATION_CODE, userContext);

                    Optional<ErrorResponse> emailErrorResponse =
                            validationService.validateEmailAddress(
                                    request.getEmail());
                    if (emailErrorResponse.isPresent()) {
                        LOGGER.error(
                                "Session: {} encountered emailErrorResponse: {}",
                                userContext.getSession().getSessionId(),
                                emailErrorResponse.get());
                        return generateApiGatewayProxyErrorResponse(
                                400, emailErrorResponse.get());
                    }
                    return handleNotificationRequest(
                            request.getEmail(),
                            request.getNotificationType(),
                            userContext.getSession(),
                            nextState);
                case VERIFY_PHONE_NUMBER:
                    nextState =
                            stateMachine.transition(
                                    userContext.getSession().getState(),
                                    SYSTEM_HAS_SENT_PHONE_VERIFICATION_CODE,
                                    userContext);

                    if (request.getPhoneNumber() == null) {
                        LOGGER.error(
                                "No phone number provided for session {}",
                                userContext.getSession().getSessionId());
                        return generateApiGatewayProxyResponse(400, ERROR_1011);
                    }
                    String phoneNumber =
                            removeWhitespaceFromPhoneNumber(
                                    request.getPhoneNumber());
                    Optional<ErrorResponse> errorResponse =
                            validationService.validatePhoneNumber(phoneNumber);
                    if (errorResponse.isPresent()) {
                        return generateApiGatewayProxyErrorResponse(
                                400, errorResponse.get());
                    }
                    return handleNotificationRequest(
                            phoneNumber,
                            request.getNotificationType(),
                            userContext.getSession(),
                            nextState);
            }
            return generateApiGatewayProxyErrorResponse(400, ERROR_1002);
        } catch (SdkClientException ex) {
            LOGGER.error("Error sending message to queue", ex);
            return generateApiGatewayProxyResponse(
                    500, "Error sending message to queue");
        } catch (JsonProcessingException e) {
            LOGGER.error("Error parsing request", e);
            return generateApiGatewayProxyErrorResponse(400, ERROR_1001);
        } catch (StateMachine.InvalidStateTransitionException e) {
            LOGGER.error("Invalid transition in user journey", e);
            return generateApiGatewayProxyErrorResponse(400, ERROR_1017);
        }
    }

    private String removeWhitespaceFromPhoneNumber(String phoneNumber) {
        return phoneNumber.replaceAll("\\s+", "");
    }

    private APIGatewayProxyResponseEvent handleNotificationRequest(
            String destination,
            NotificationType notificationType,
            Session session,
            SessionState nextState)
            throws JsonProcessingException {

        String code = codeGeneratorService.sixDigitCode();
        NotifyRequest notifyRequest = new NotifyRequest(destination, notificationType, code);
        codeStorageService.saveOtpCode(
                session.getEmailAddress(),
                code,
                configurationService.getCodeExpiry(),
                notificationType);
        sessionService.save(session.setState(nextState).incrementCodeRequestCount());
        sqsClient.send(objectMapper.writeValueAsString((notifyRequest)));
        LOGGER.info(
                "SendNotificationHandler successfully processed request for session {}",
                session.getSessionId());
        return generateApiGatewayProxyResponse(200, new BaseAPIResponse(session.getState()));
    }

    private boolean isCodeRequestAttemptValid(
            String email, Session session, NotificationType notificationType, UserContext userContext) {
        if (session.getCodeRequestCount() == configurationService.getCodeMaxRetries()) {
            LOGGER.error(
                    "User has requested too many OTP codes for session {}", session.getSessionId());
            codeStorageService.saveCodeRequestBlockedForSession(
                    email, session.getSessionId(), configurationService.getCodeExpiry());
            SessionState nextState =
                    stateMachine.transition(
                            session.getState(),
                            getSessionActionForCodeRequestLimitReached(notificationType),
                            userContext);
            sessionService.save(session.setState(nextState).resetCodeRequestCount());
            return false;
        }
        if (codeStorageService.isCodeRequestBlockedForSession(email, session.getSessionId())) {
            LOGGER.error(
                    "User is blocked from requesting any OTP codes for session {}",
                    session.getSessionId());
            SessionState nextState =
                    stateMachine.transition(
                            session.getState(),
                            getSessionActionForMaxCodeRequests(notificationType));
            sessionService.save(session.setState(nextState));
            return false;
        }
        return true;
    }

    private SessionAction getSessionActionForCodeRequestLimitReached(
            NotificationType notificationType) {
        switch (notificationType) {
            case VERIFY_EMAIL:
                return SYSTEM_HAS_SENT_TOO_MANY_EMAIL_VERIFICATION_CODES;
            case VERIFY_PHONE_NUMBER:
                return SYSTEM_HAS_SENT_TOO_MANY_PHONE_VERIFICATION_CODES;
            default:
                LOGGER.error("Invalid NotificationType sent");
                throw new RuntimeException("Invalid NotificationType sent");
        }
    }

    private SessionAction getSessionActionForMaxCodeRequests(NotificationType notificationType) {
        switch (notificationType) {
            case VERIFY_EMAIL:
                return SYSTEM_IS_BLOCKED_FROM_SENDING_ANY_EMAIL_VERIFICATION_CODES;
            case VERIFY_PHONE_NUMBER:
                return SYSTEM_IS_BLOCKED_FROM_SENDING_ANY_PHONE_VERIFICATION_CODES;
            default:
                LOGGER.error("Invalid NotificationType sent");
                throw new RuntimeException("Invalid NotificationType sent");
        }
    }
}

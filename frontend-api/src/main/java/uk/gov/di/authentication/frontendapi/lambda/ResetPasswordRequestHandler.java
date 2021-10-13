package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.core.exception.SdkClientException;
import uk.gov.di.authentication.frontendapi.entity.ResetPasswordRequest;
import uk.gov.di.authentication.frontendapi.services.AwsSqsClient;
import uk.gov.di.authentication.shared.entity.BaseAPIResponse;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.entity.NotifyRequest;
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
import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1017;
import static uk.gov.di.authentication.shared.entity.SessionAction.SYSTEM_HAS_SENT_RESET_PASSWORD_LINK;
import static uk.gov.di.authentication.shared.entity.SessionAction.SYSTEM_HAS_SENT_RESET_PASSWORD_LINK_TOO_MANY_TIMES;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.state.StateMachine.userJourneyStateMachine;

public class ResetPasswordRequestHandler extends BaseFrontendHandler<ResetPasswordRequest>
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER = LoggerFactory.getLogger(ResetPasswordRequestHandler.class);

    private final ValidationService validationService;
    private final AwsSqsClient sqsClient;
    private final CodeGeneratorService codeGeneratorService;
    private final CodeStorageService codeStorageService;
    private final StateMachine<SessionState, SessionAction, UserContext> stateMachine =
            userJourneyStateMachine();

    public ResetPasswordRequestHandler(
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
                ResetPasswordRequest.class,
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

    public ResetPasswordRequestHandler() {
        super(ResetPasswordRequest.class, ConfigurationService.getInstance());
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
            APIGatewayProxyRequestEvent input,
            Context context,
            ResetPasswordRequest request,
            UserContext userContext) {
        LOGGER.info(
                "ResetPasswordRequestHandler processing request for session: {}",
                userContext.getSession().getSessionId());
        try {
            if (!userContext.getSession().validateSession(request.getEmail())) {
                LOGGER.info(
                        "Invalid session. session: {}", userContext.getSession().getSessionId());
                return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1000);
            }
            Optional<ErrorResponse> emailErrorResponse =
                    validationService.validateEmailAddress(request.getEmail());
            if (emailErrorResponse.isPresent()) {
                LOGGER.info(
                        "Email validation failed: {} for session: {}",
                        emailErrorResponse.get(),
                        userContext.getSession().getSessionId());
                return generateApiGatewayProxyErrorResponse(400, emailErrorResponse.get());
            }

            Optional<ErrorResponse> errorResponse =
                    validatePasswordResetCount(request.getEmail(), userContext);
            if (errorResponse.isPresent()) {
                return generateApiGatewayProxyErrorResponse(400, errorResponse.get());
            }
            return processPasswordResetRequest(
                    request.getEmail(), NotificationType.RESET_PASSWORD, userContext);

        } catch (SdkClientException ex) {
            LOGGER.error(
                    "Error sending message to queue for session: {}",
                    userContext.getSession().getSessionId(),
                    ex);
            return generateApiGatewayProxyResponse(500, "Error sending message to queue");
        } catch (JsonProcessingException e) {
            LOGGER.error(
                    "Error parsing request for session: {}",
                    userContext.getSession().getSessionId(),
                    e);
            return generateApiGatewayProxyErrorResponse(400, ERROR_1001);
        } catch (StateMachine.InvalidStateTransitionException e) {
            LOGGER.error(
                    "Invalid transition in user journey for session: {}",
                    userContext.getSession().getSessionId(),
                    e);
            return generateApiGatewayProxyErrorResponse(400, ERROR_1017);
        }
    }

    private APIGatewayProxyResponseEvent processPasswordResetRequest(
            String email, NotificationType notificationType, UserContext userContext)
            throws JsonProcessingException {
        SessionState nextState =
                stateMachine.transition(
                        userContext.getSession().getState(),
                        SYSTEM_HAS_SENT_RESET_PASSWORD_LINK,
                        userContext);
        String subjectId = authenticationService.getSubjectFromEmail(email).getValue();
        String code = codeGeneratorService.twentyByteEncodedRandomCode();
        NotifyRequest notifyRequest = new NotifyRequest(email, notificationType, code);
        codeStorageService.savePasswordResetCode(
                subjectId,
                code,
                configurationService.getCodeExpiry(),
                NotificationType.RESET_PASSWORD);
        sessionService.save(
                userContext.getSession().setState(nextState).incrementPasswordResetCount());
        sqsClient.send(serialiseRequest(notifyRequest));
        LOGGER.info(
                "ResetPasswordRequestHandler successfully processed request for session: {}",
                userContext.getSession().getSessionId());
        return generateApiGatewayProxyResponse(
                200, new BaseAPIResponse(userContext.getSession().getState()));
    }

    private Optional<ErrorResponse> validatePasswordResetCount(
            String email, UserContext userContext) {
        if (codeStorageService.isPasswordResetBlockedForSession(
                email, userContext.getSession().getSessionId())) {
            LOGGER.info(
                    "User cannot request another password reset for session: {}",
                    userContext.getSession().getSessionId());
            return Optional.of(ErrorResponse.ERROR_1023);
        } else if (userContext.getSession().getPasswordResetCount()
                > configurationService.getCodeMaxRetries()) {
            LOGGER.info(
                    "User has requested too many password resets for session: {}",
                    userContext.getSession().getSessionId());
            codeStorageService.savePasswordResetBlockedForSession(
                    userContext.getSession().getEmailAddress(),
                    userContext.getSession().getSessionId(),
                    configurationService.getCodeExpiry());
            sessionService.save(userContext.getSession().resetPasswordResetCount());
            SessionState nextState =
                    stateMachine.transition(
                            userContext.getSession().getState(),
                            SYSTEM_HAS_SENT_RESET_PASSWORD_LINK_TOO_MANY_TIMES,
                            userContext);
            sessionService.save(userContext.getSession().setState(nextState));
            return Optional.of(ErrorResponse.ERROR_1022);
        }
        return Optional.empty();
    }

    private String serialiseRequest(Object request) throws JsonProcessingException {
        return objectMapper.writeValueAsString(request);
    }
}

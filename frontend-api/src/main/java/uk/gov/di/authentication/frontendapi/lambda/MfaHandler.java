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
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.NotifyRequest;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.SessionAction;
import uk.gov.di.authentication.shared.entity.SessionState;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.CodeGeneratorService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.state.StateMachine;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.Optional;

import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1000;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1001;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1014;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1017;
import static uk.gov.di.authentication.shared.entity.NotificationType.MFA_SMS;
import static uk.gov.di.authentication.shared.entity.SessionAction.SYSTEM_HAS_SENT_MFA_CODE;
import static uk.gov.di.authentication.shared.entity.SessionAction.SYSTEM_HAS_SENT_TOO_MANY_MFA_CODES;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.WarmerHelper.isWarming;
import static uk.gov.di.authentication.shared.state.StateMachine.userJourneyStateMachine;

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
    private final StateMachine<SessionState, SessionAction, UserContext> stateMachine =
            userJourneyStateMachine();

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
        return isWarming(input)
                .orElseGet(
                        () -> {
                            Session session =
                                    sessionService
                                            .getSessionFromRequestHeaders(input.getHeaders())
                                            .orElse(null);
                            if (session == null) {
                                LOGGER.error("Session cannot be found");
                                return generateApiGatewayProxyErrorResponse(400, ERROR_1000);
                            } else {
                                LOGGER.info(
                                        "MfaHandler processing request for session {}",
                                        session.getSessionId());
                            }

                            try {
                                var nextState =
                                        stateMachine.transition(
                                                session.getState(), SYSTEM_HAS_SENT_MFA_CODE);

                                UserWithEmailRequest userWithEmailRequest =
                                        objectMapper.readValue(
                                                input.getBody(), UserWithEmailRequest.class);
                                Optional<ErrorResponse> codeRequestError =
                                        validateCodeRequestAttempts(
                                                userWithEmailRequest.getEmail(), session);
                                if (codeRequestError.isPresent()) {
                                    return generateApiGatewayProxyErrorResponse(
                                            400, codeRequestError.get());
                                }
                                if (!session.validateSession(userWithEmailRequest.getEmail())) {
                                    LOGGER.error(
                                            "Email in session does not match Email in Request");
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
                                sessionService.save(
                                        session.setState(nextState).incrementCodeRequestCount());
                                NotifyRequest notifyRequest =
                                        new NotifyRequest(phoneNumber, MFA_SMS, code);
                                sqsClient.send(objectMapper.writeValueAsString(notifyRequest));

                                LOGGER.info(
                                        "MfaHandler successfully processed request for session {}",
                                        session.getSessionId());

                                return generateApiGatewayProxyResponse(
                                        200, new BaseAPIResponse(session.getState()));
                            } catch (JsonProcessingException e) {
                                LOGGER.error(
                                        "Request is missing parameters. Request Body: {}",
                                        input.getBody());
                                return generateApiGatewayProxyErrorResponse(400, ERROR_1001);
                            } catch (StateMachine.InvalidStateTransitionException e) {
                                LOGGER.error("Invalid transition in user journey", e);
                                return generateApiGatewayProxyErrorResponse(400, ERROR_1017);
                            }
                        });
    }

    private Optional<ErrorResponse> validateCodeRequestAttempts(String email, Session session) {
        if (session.getCodeRequestCount() == configurationService.getCodeMaxRetries()) {
            LOGGER.error("User has requested too many OTP codes");
            codeStorageService.saveCodeRequestBlockedForSession(
                    email, session.getSessionId(), configurationService.getCodeExpiry());
            SessionState nextState =
                    stateMachine.transition(session.getState(), SYSTEM_HAS_SENT_TOO_MANY_MFA_CODES);
            sessionService.save(session.setState(nextState).resetCodeRequestCount());
            return Optional.of(ErrorResponse.ERROR_1024);
        }
        if (codeStorageService.isCodeRequestBlockedForSession(email, session.getSessionId())) {
            LOGGER.error("User is blocked from requesting any OTP codes");
            return Optional.of(ErrorResponse.ERROR_1025);
        }
        return Optional.empty();
    }
}

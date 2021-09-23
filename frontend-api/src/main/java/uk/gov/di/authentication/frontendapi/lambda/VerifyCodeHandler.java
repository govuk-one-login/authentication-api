package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.authentication.frontendapi.entity.VerifyCodeRequest;
import uk.gov.di.authentication.shared.entity.BaseAPIResponse;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.SessionAction;
import uk.gov.di.authentication.shared.entity.SessionState;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.services.ValidationService;
import uk.gov.di.authentication.shared.state.StateMachine;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.util.Map.entry;
import static uk.gov.di.authentication.shared.entity.NotificationType.MFA_SMS;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_EMAIL;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_PHONE_NUMBER;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_INVALID_EMAIL_VERIFICATION_CODE_TOO_MANY_TIMES;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_INVALID_MFA_CODE_TOO_MANY_TIMES;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_INVALID_PHONE_VERIFICATION_CODE_TOO_MANY_TIMES;
import static uk.gov.di.authentication.shared.entity.SessionState.EMAIL_CODE_MAX_RETRIES_REACHED;
import static uk.gov.di.authentication.shared.entity.SessionState.EMAIL_CODE_VERIFIED;
import static uk.gov.di.authentication.shared.entity.SessionState.MFA_CODE_MAX_RETRIES_REACHED;
import static uk.gov.di.authentication.shared.entity.SessionState.MFA_CODE_VERIFIED;
import static uk.gov.di.authentication.shared.entity.SessionState.PHONE_NUMBER_CODE_MAX_RETRIES_REACHED;
import static uk.gov.di.authentication.shared.entity.SessionState.UPDATED_TERMS_AND_CONDITIONS;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.state.StateMachine.userJourneyStateMachine;

public class VerifyCodeHandler extends BaseFrontendHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LoggerFactory.getLogger(VerifyCodeHandler.class);

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final CodeStorageService codeStorageService;
    private final ValidationService validationService;
    private final StateMachine<SessionState, SessionAction, UserContext> stateMachine;

    protected VerifyCodeHandler(
            ConfigurationService configurationService,
            SessionService sessionService,
            ClientSessionService clientSessionService,
            ClientService clientService,
            AuthenticationService authenticationService,
            CodeStorageService codeStorageService,
            ValidationService validationService,
            StateMachine<SessionState, SessionAction, UserContext> stateMachine) {
        super(
                configurationService,
                sessionService,
                clientSessionService,
                clientService,
                authenticationService);
        this.codeStorageService = codeStorageService;
        this.validationService = validationService;
        this.stateMachine = stateMachine;
    }

    public VerifyCodeHandler() {
        super(ConfigurationService.getInstance());
        this.codeStorageService =
                new CodeStorageService(
                        new RedisConnectionService(ConfigurationService.getInstance()));
        this.validationService = new ValidationService();
        this.stateMachine = userJourneyStateMachine();
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequestWithUserContext(
            APIGatewayProxyRequestEvent input, Context context, UserContext userContext) {
        try {
            VerifyCodeRequest codeRequest =
                    objectMapper.readValue(input.getBody(), VerifyCodeRequest.class);

            var session = userContext.getSession();

            var blockedCodeBehaviour =
                    Map.ofEntries(
                            entry(
                                    VERIFY_EMAIL,
                                    USER_ENTERED_INVALID_EMAIL_VERIFICATION_CODE_TOO_MANY_TIMES),
                            entry(
                                    VERIFY_PHONE_NUMBER,
                                    USER_ENTERED_INVALID_PHONE_VERIFICATION_CODE_TOO_MANY_TIMES),
                            entry(MFA_SMS, USER_ENTERED_INVALID_MFA_CODE_TOO_MANY_TIMES));

            if (isCodeBlockedForSession(session)) {
                sessionService.save(
                        session.setState(
                                stateMachine.transition(
                                        session.getState(),
                                        blockedCodeBehaviour.get(codeRequest.getNotificationType()),
                                        userContext)));
                return generateSuccessResponse(session);
            }

            switch (codeRequest.getNotificationType()) {
                case VERIFY_EMAIL:
                    Optional<String> emailCode =
                            codeStorageService.getOtpCode(
                                    session.getEmailAddress(), codeRequest.getNotificationType());
                    sessionService.save(
                            session.setState(
                                    stateMachine.transition(
                                            session.getState(),
                                            validationService.validateEmailVerificationCode(
                                                    emailCode,
                                                    codeRequest.getCode(),
                                                    session,
                                                    configurationService.getCodeMaxRetries()),
                                            userContext)));
                    processCodeSessionState(session, codeRequest.getNotificationType());
                    return generateSuccessResponse(session);
                case VERIFY_PHONE_NUMBER:
                    Optional<String> phoneNumberCode =
                            codeStorageService.getOtpCode(
                                    session.getEmailAddress(), codeRequest.getNotificationType());
                    sessionService.save(
                            session.setState(
                                    stateMachine.transition(
                                            session.getState(),
                                            validationService.validatePhoneVerificationCode(
                                                    phoneNumberCode,
                                                    codeRequest.getCode(),
                                                    session,
                                                    configurationService.getCodeMaxRetries()),
                                            userContext)));
                    processCodeSessionState(session, codeRequest.getNotificationType());
                    return generateSuccessResponse(session);
                case MFA_SMS:
                    Optional<String> mfaCode =
                            codeStorageService.getOtpCode(
                                    session.getEmailAddress(), codeRequest.getNotificationType());

                    sessionService.save(
                            session.setState(
                                    stateMachine.transition(
                                            session.getState(),
                                            validationService.validateMfaVerificationCode(
                                                    mfaCode,
                                                    codeRequest.getCode(),
                                                    session,
                                                    configurationService.getCodeMaxRetries()),
                                            userContext)));
                    processCodeSessionState(session, codeRequest.getNotificationType());
                    return generateSuccessResponse(session);
            }
        } catch (JsonProcessingException e) {
            LOG.error("Error parsing request", e);
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        } catch (StateMachine.InvalidStateTransitionException e) {
            LOG.error("Invalid transition in user journey", e);
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1017);
        }
        LOG.error(
                "Encountered unexpected error while processing session {}",
                userContext.getSession().getSessionId());
        return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1002);
    }

    private boolean isCodeBlockedForSession(Session session) {
        return codeStorageService.isCodeBlockedForSession(
                session.getEmailAddress(), session.getSessionId());
    }

    private APIGatewayProxyResponseEvent generateSuccessResponse(Session session)
            throws JsonProcessingException {
        LOG.info(
                "VerifyCodeHandler successfully processed request for session {}",
                session.getSessionId());

        return generateApiGatewayProxyResponse(200, new BaseAPIResponse(session.getState()));
    }

    private void blockCodeForSessionAndResetCount(Session session) {
        codeStorageService.saveCodeBlockedForSession(
                session.getEmailAddress(),
                session.getSessionId(),
                configurationService.getCodeExpiry());
        sessionService.save(session.resetRetryCount());
    }

    private void processCodeSessionState(Session session, NotificationType notificationType) {
        if (session.getState().equals(SessionState.PHONE_NUMBER_CODE_VERIFIED)) {
            codeStorageService.deleteOtpCode(session.getEmailAddress(), notificationType);
            authenticationService.updatePhoneNumberVerifiedStatus(session.getEmailAddress(), true);
        } else if (List.of(EMAIL_CODE_VERIFIED, MFA_CODE_VERIFIED, UPDATED_TERMS_AND_CONDITIONS)
                .contains(session.getState())) {
            codeStorageService.deleteOtpCode(session.getEmailAddress(), notificationType);
        } else if (List.of(
                        PHONE_NUMBER_CODE_MAX_RETRIES_REACHED,
                        EMAIL_CODE_MAX_RETRIES_REACHED,
                        MFA_CODE_MAX_RETRIES_REACHED)
                .contains(session.getState())) {
            blockCodeForSessionAndResetCount(session);
        }
    }
}

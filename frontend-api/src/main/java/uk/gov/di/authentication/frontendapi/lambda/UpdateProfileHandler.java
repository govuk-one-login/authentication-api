package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.authentication.frontendapi.entity.UpdateProfileRequest;
import uk.gov.di.authentication.shared.entity.BaseAPIResponse;
import uk.gov.di.authentication.shared.entity.ClientConsent;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.SessionAction;
import uk.gov.di.authentication.shared.entity.SessionState;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.ValidScopes;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.state.StateMachine;
import uk.gov.di.authentication.shared.state.StateMachine.InvalidStateTransitionException;
import uk.gov.di.authentication.shared.state.UserContext;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Optional;
import java.util.Set;

import static uk.gov.di.authentication.shared.domain.AccountManagementAuditableEvent.ACCOUNT_MANAGEMENT_CONSENT_UPDATED;
import static uk.gov.di.authentication.shared.domain.AccountManagementAuditableEvent.ACCOUNT_MANAGEMENT_PHONE_NUMBER_UPDATED;
import static uk.gov.di.authentication.shared.domain.AccountManagementAuditableEvent.ACCOUNT_MANAGEMENT_REQUEST_ERROR;
import static uk.gov.di.authentication.shared.domain.AccountManagementAuditableEvent.ACCOUNT_MANAGEMENT_REQUEST_RECEIVED;
import static uk.gov.di.authentication.shared.domain.AccountManagementAuditableEvent.ACCOUNT_MANAGEMENT_TERMS_CONDS_ACCEPTANCE_UPDATED;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ACCEPTS_TERMS_AND_CONDITIONS;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_A_NEW_PHONE_NUMBER;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_HAS_ACTIONED_CONSENT;
import static uk.gov.di.authentication.shared.entity.SessionState.ADDED_UNVERIFIED_PHONE_NUMBER;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.state.StateMachine.userJourneyStateMachine;

public class UpdateProfileHandler extends BaseFrontendHandler<UpdateProfileRequest>
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER = LoggerFactory.getLogger(UpdateProfileHandler.class);

    private final AuthenticationService authenticationService;
    private final SessionService sessionService;
    private final ConfigurationService configurationService;
    private final AuditService auditService;
    private final StateMachine<SessionState, SessionAction, UserContext> stateMachine;

    protected UpdateProfileHandler(
            AuthenticationService authenticationService,
            SessionService sessionService,
            ClientSessionService clientSessionService,
            ConfigurationService configurationService,
            AuditService auditService,
            ClientService clientService,
            StateMachine<SessionState, SessionAction, UserContext> stateMachine) {
        super(
                UpdateProfileRequest.class,
                configurationService,
                sessionService,
                clientSessionService,
                clientService,
                authenticationService);
        this.authenticationService = authenticationService;
        this.sessionService = sessionService;
        this.configurationService = configurationService;
        this.auditService = auditService;
        this.stateMachine = stateMachine;
    }

    public UpdateProfileHandler() {
        super(UpdateProfileRequest.class, ConfigurationService.getInstance());
        configurationService = new ConfigurationService();
        this.authenticationService =
                new DynamoService(
                        configurationService.getAwsRegion(),
                        configurationService.getEnvironment(),
                        configurationService.getDynamoEndpointUri());
        sessionService = new SessionService(configurationService);
        auditService = new AuditService();
        this.stateMachine = userJourneyStateMachine();
    }

    @Override
    public void onRequestReceived(Context context) {
        auditService.submitAuditEvent(
                ACCOUNT_MANAGEMENT_REQUEST_RECEIVED,
                context.getAwsRequestId(),
                AuditService.UNKNOWN,
                AuditService.UNKNOWN,
                AuditService.UNKNOWN,
                AuditService.UNKNOWN);
    }

    @Override
    public void onRequestValidationError(Context context) {
        auditService.submitAuditEvent(
                ACCOUNT_MANAGEMENT_REQUEST_ERROR,
                context.getAwsRequestId(),
                AuditService.UNKNOWN,
                AuditService.UNKNOWN,
                AuditService.UNKNOWN,
                AuditService.UNKNOWN);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequestWithUserContext(
            APIGatewayProxyRequestEvent input,
            Context context,
            UpdateProfileRequest request,
            UserContext userContext) {
        Session session = userContext.getSession();

        LOGGER.info(
                "UpdateProfileHandler processing request for session {}", session.getSessionId());

        String ipAddress = IpAddressHelper.extractIpAddress(input);

        try {
            if (!session.validateSession(request.getEmail())) {
                LOGGER.info("Invalid session. Email {}", request.getEmail());
                return generateErrorResponse(ErrorResponse.ERROR_1000, context);
            }
            switch (request.getUpdateProfileType()) {
                case ADD_PHONE_NUMBER:
                    {
                        var nextState =
                                stateMachine.transition(
                                        session.getState(), USER_ENTERED_A_NEW_PHONE_NUMBER);
                        authenticationService.updatePhoneNumber(
                                request.getEmail(), request.getProfileInformation());
                        auditService.submitAuditEvent(
                                ACCOUNT_MANAGEMENT_PHONE_NUMBER_UPDATED,
                                context.getAwsRequestId(),
                                session.getSessionId(),
                                AuditService.UNKNOWN,
                                session.getEmailAddress(),
                                ipAddress);
                        sessionService.save(session.setState(nextState));
                        LOGGER.info(
                                "Phone number updated and session state changed. Session state {}",
                                ADDED_UNVERIFIED_PHONE_NUMBER);
                        return generateSuccessResponse(session);
                    }
                case CAPTURE_CONSENT:
                    {
                        ClientSession clientSession = userContext.getClientSession();

                        if (clientSession == null) {
                            LOGGER.info("ClientSession not found");
                            return generateErrorResponse(ErrorResponse.ERROR_1000, context);
                        }
                        AuthenticationRequest authorizationRequest;
                        try {
                            authorizationRequest =
                                    AuthenticationRequest.parse(
                                            clientSession.getAuthRequestParams());
                        } catch (ParseException e) {
                            LOGGER.info(
                                    "Cannot retrieve auth request params from client session id.");
                            return generateErrorResponse(ErrorResponse.ERROR_1001, context);
                        }
                        String clientId = authorizationRequest.getClientID().getValue();
                        Set<String> claimsConsented;

                        if (!Boolean.parseBoolean(request.getProfileInformation())) {
                            claimsConsented = OIDCScopeValue.OPENID.getClaimNames();
                        } else {
                            claimsConsented =
                                    ValidScopes.getClaimsForListOfScopes(
                                            authorizationRequest.getScope().toStringList());
                        }

                        processAndUpdateClientConsent(
                                request.getEmail(), userContext, clientId, claimsConsented);

                        var nextState =
                                stateMachine.transition(
                                        session.getState(), USER_HAS_ACTIONED_CONSENT);

                        sessionService.save(session.setState(nextState));

                        auditService.submitAuditEvent(
                                ACCOUNT_MANAGEMENT_CONSENT_UPDATED,
                                context.getAwsRequestId(),
                                session.getSessionId(),
                                clientId,
                                session.getEmailAddress(),
                                ipAddress);

                        LOGGER.info(
                                "Consent updated for ClientID {} and session state changed. Session state {}",
                                clientId,
                                nextState);

                        return generateSuccessResponse(session);
                    }
                case UPDATE_TERMS_CONDS:
                    {
                        authenticationService.updateTermsAndConditions(
                                request.getEmail(),
                                configurationService.getTermsAndConditionsVersion());

                        auditService.submitAuditEvent(
                                ACCOUNT_MANAGEMENT_TERMS_CONDS_ACCEPTANCE_UPDATED,
                                context.getAwsRequestId(),
                                session.getSessionId(),
                                AuditService.UNKNOWN,
                                session.getEmailAddress(),
                                ipAddress);
                        LOGGER.info(
                                "Updated terms and conditions. Email {} for Version {}",
                                request.getEmail(),
                                configurationService.getTermsAndConditionsVersion());

                        var nextState =
                                stateMachine.transition(
                                        session.getState(),
                                        USER_ACCEPTS_TERMS_AND_CONDITIONS,
                                        userContext);
                        sessionService.save(session.setState(nextState));

                        LOGGER.info("Updated terms and conditions. Session state {}", nextState);

                        return generateSuccessResponse(session);
                    }
            }
        } catch (JsonProcessingException e) {
            LOGGER.error("Error parsing request", e);
            return generateErrorResponse(ErrorResponse.ERROR_1001, context);
        } catch (InvalidStateTransitionException e) {
            LOGGER.error("Invalid transition in user journey", e);
            return generateErrorResponse(ErrorResponse.ERROR_1017, context);
        }
        LOGGER.error(
                "Encountered unexpected error while processing session {}", session.getSessionId());
        return generateErrorResponse(ErrorResponse.ERROR_1013, context);
    }

    private void processAndUpdateClientConsent(
            String email, UserContext userContext, String clientId, Set<String> claimsConsented) {
        Optional<ClientConsent> clientConsentForClientId =
                userContext
                        .getUserProfile()
                        .map(UserProfile::getClientConsent)
                        .flatMap(
                                t ->
                                        t.stream()
                                                .filter(
                                                        consent ->
                                                                consent.getClientId()
                                                                        .equals(clientId))
                                                .findFirst());

        ClientConsent clientConsentToUpdate =
                clientConsentForClientId
                        .map(t -> t.setClaims(claimsConsented))
                        .orElse(
                                new ClientConsent(
                                        clientId,
                                        claimsConsented,
                                        LocalDateTime.now(ZoneId.of("UTC")).toString()));

        LOGGER.info(
                "Consent value successfully added to ClientConsentObject. Attempting to update UserProfile with ClientConsent: {}",
                clientConsentToUpdate);

        authenticationService.updateConsent(email, clientConsentToUpdate);
    }

    private APIGatewayProxyResponseEvent generateSuccessResponse(Session session)
            throws JsonProcessingException {
        LOGGER.info(
                "UpdateProfileHandler successfully processed request for session {}",
                session.getSessionId());

        return generateApiGatewayProxyResponse(200, new BaseAPIResponse(session.getState()));
    }

    private APIGatewayProxyResponseEvent generateErrorResponse(
            ErrorResponse errorResponse, Context context) {
        onRequestValidationError(context);
        return generateApiGatewayProxyErrorResponse(400, errorResponse);
    }
}

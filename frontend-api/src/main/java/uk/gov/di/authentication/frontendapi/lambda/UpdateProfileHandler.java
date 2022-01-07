package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
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
import uk.gov.di.authentication.shared.helpers.LogLineHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.lambda.BaseFrontendHandler;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.state.StateMachine;
import uk.gov.di.authentication.shared.state.StateMachine.InvalidStateTransitionException;
import uk.gov.di.authentication.shared.state.UserContext;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Optional;
import java.util.Set;

import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.UPDATE_PROFILE_CONSENT_UPDATED;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.UPDATE_PROFILE_PHONE_NUMBER;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.UPDATE_PROFILE_REQUEST_ERROR;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.UPDATE_PROFILE_REQUEST_RECEIVED;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.UPDATE_PROFILE_TERMS_CONDS_ACCEPTANCE;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ACCEPTS_TERMS_AND_CONDITIONS;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_A_NEW_PHONE_NUMBER;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_HAS_ACTIONED_CONSENT;
import static uk.gov.di.authentication.shared.entity.SessionState.ADDED_UNVERIFIED_PHONE_NUMBER;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.CLIENT_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.PERSISTENT_SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.authentication.shared.state.StateMachine.userJourneyStateMachine;

public class UpdateProfileHandler extends BaseFrontendHandler<UpdateProfileRequest>
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(UpdateProfileHandler.class);

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
        this.auditService = auditService;
        this.stateMachine = stateMachine;
    }

    public UpdateProfileHandler() {
        this(ConfigurationService.getInstance());
    }

    public UpdateProfileHandler(ConfigurationService configurationService) {
        super(UpdateProfileRequest.class, configurationService);
        auditService = new AuditService(configurationService);
        this.stateMachine = userJourneyStateMachine();
    }

    @Override
    public void onRequestReceived(Context context) {
        auditService.submitAuditEvent(
                UPDATE_PROFILE_REQUEST_RECEIVED,
                context.getAwsRequestId(),
                AuditService.UNKNOWN,
                AuditService.UNKNOWN,
                AuditService.UNKNOWN,
                AuditService.UNKNOWN,
                AuditService.UNKNOWN,
                AuditService.UNKNOWN,
                AuditService.UNKNOWN);
    }

    @Override
    public void onRequestValidationError(Context context) {
        auditService.submitAuditEvent(
                UPDATE_PROFILE_REQUEST_ERROR,
                context.getAwsRequestId(),
                AuditService.UNKNOWN,
                AuditService.UNKNOWN,
                AuditService.UNKNOWN,
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

        String persistentSessionId =
                PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders());

        LogLineHelper.attachSessionIdToLogs(session);
        attachLogFieldToLogs(PERSISTENT_SESSION_ID, persistentSessionId);

        LOG.info("Processing request");

        String ipAddress = IpAddressHelper.extractIpAddress(input);

        try {
            if (!session.validateSession(request.getEmail())) {
                LOG.info("Invalid session");
                return generateErrorResponse(ErrorResponse.ERROR_1000, context);
            }

            String email = session.getEmailAddress();
            var userProfile =
                    Optional.ofNullable(authenticationService.getUserProfileByEmail(email));

            switch (request.getUpdateProfileType()) {
                case ADD_PHONE_NUMBER:
                    {
                        var nextState =
                                stateMachine.transition(
                                        session.getState(),
                                        USER_ENTERED_A_NEW_PHONE_NUMBER,
                                        userContext);
                        authenticationService.updatePhoneNumber(
                                request.getEmail(), request.getProfileInformation());
                        auditService.submitAuditEvent(
                                UPDATE_PROFILE_PHONE_NUMBER,
                                context.getAwsRequestId(),
                                session.getSessionId(),
                                AuditService.UNKNOWN,
                                userProfile
                                        .map(UserProfile::getSubjectID)
                                        .orElse(AuditService.UNKNOWN),
                                email,
                                ipAddress,
                                request.getProfileInformation(),
                                persistentSessionId);
                        sessionService.save(session.setState(nextState));
                        LOG.info(
                                "Phone number updated and session state updated to {}",
                                ADDED_UNVERIFIED_PHONE_NUMBER);
                        return generateSuccessResponse(session);
                    }
                case CAPTURE_CONSENT:
                    {
                        ClientSession clientSession = userContext.getClientSession();

                        if (clientSession == null) {
                            LOG.error("ClientSession not found");
                            return generateErrorResponse(ErrorResponse.ERROR_1000, context);
                        }
                        AuthenticationRequest authorizationRequest;
                        try {
                            authorizationRequest =
                                    AuthenticationRequest.parse(
                                            clientSession.getAuthRequestParams());
                        } catch (ParseException e) {
                            LOG.info("Cannot retrieve auth request params from client session id");
                            return generateErrorResponse(ErrorResponse.ERROR_1001, context);
                        }
                        String clientId = authorizationRequest.getClientID().getValue();

                        attachLogFieldToLogs(CLIENT_ID, clientId);

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
                                        session.getState(), USER_HAS_ACTIONED_CONSENT, userContext);

                        sessionService.save(session.setState(nextState));

                        auditService.submitAuditEvent(
                                UPDATE_PROFILE_CONSENT_UPDATED,
                                context.getAwsRequestId(),
                                session.getSessionId(),
                                clientId,
                                userProfile
                                        .map(UserProfile::getSubjectID)
                                        .orElse(AuditService.UNKNOWN),
                                email,
                                ipAddress,
                                userProfile
                                        .map(UserProfile::getPhoneNumber)
                                        .orElse(AuditService.UNKNOWN),
                                persistentSessionId);

                        LOG.info("Consent updated and session state changed to {}", nextState);

                        return generateSuccessResponse(session);
                    }
                case UPDATE_TERMS_CONDS:
                    {
                        authenticationService.updateTermsAndConditions(
                                request.getEmail(),
                                configurationService.getTermsAndConditionsVersion());

                        auditService.submitAuditEvent(
                                UPDATE_PROFILE_TERMS_CONDS_ACCEPTANCE,
                                context.getAwsRequestId(),
                                session.getSessionId(),
                                AuditService.UNKNOWN,
                                userProfile
                                        .map(UserProfile::getSubjectID)
                                        .orElse(AuditService.UNKNOWN),
                                email,
                                ipAddress,
                                userProfile
                                        .map(UserProfile::getPhoneNumber)
                                        .orElse(AuditService.UNKNOWN),
                                persistentSessionId);
                        LOG.info(
                                "Updated terms and conditions to version {}",
                                configurationService.getTermsAndConditionsVersion());

                        var nextState =
                                stateMachine.transition(
                                        session.getState(),
                                        USER_ACCEPTS_TERMS_AND_CONDITIONS,
                                        userContext);
                        sessionService.save(session.setState(nextState));

                        LOG.info("Updated terms and conditions session state to {}", nextState);

                        return generateSuccessResponse(session);
                    }
            }
        } catch (JsonProcessingException e) {
            LOG.error("Error parsing request");
            return generateErrorResponse(ErrorResponse.ERROR_1001, context);
        } catch (InvalidStateTransitionException e) {
            return generateErrorResponse(ErrorResponse.ERROR_1017, context);
        }
        LOG.error("Encountered unexpected error");
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

        LOG.info("Consent value successfully added. Attempting to update UserProfile.");

        authenticationService.updateConsent(email, clientConsentToUpdate);
    }

    private APIGatewayProxyResponseEvent generateSuccessResponse(Session session)
            throws JsonProcessingException {
        LOG.info("UpdateProfileHandler successfully processed request");

        return generateApiGatewayProxyResponse(200, new BaseAPIResponse(session.getState()));
    }

    private APIGatewayProxyResponseEvent generateErrorResponse(
            ErrorResponse errorResponse, Context context) {
        onRequestValidationError(context);
        return generateApiGatewayProxyErrorResponse(400, errorResponse);
    }
}

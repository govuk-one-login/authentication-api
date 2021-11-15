package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.OIDCError;
import com.nimbusds.openid.connect.sdk.Prompt;
import org.apache.http.client.utils.URIBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.authentication.oidc.domain.OidcAuditableEvent;
import uk.gov.di.authentication.oidc.entity.ResponseHeaders;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.SessionAction;
import uk.gov.di.authentication.shared.entity.SessionState;
import uk.gov.di.authentication.shared.exceptions.ClientNotFoundException;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthorizationService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.state.StateMachine;
import uk.gov.di.authentication.shared.state.UserContext;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import static java.lang.String.format;
import static uk.gov.di.authentication.oidc.entity.RequestParameters.COOKIE_CONSENT;
import static uk.gov.di.authentication.oidc.entity.RequestParameters.GA;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_HAS_STARTED_A_NEW_JOURNEY;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_HAS_STARTED_A_NEW_JOURNEY_WITH_LOGIN_REQUIRED;
import static uk.gov.di.authentication.shared.entity.SessionState.INTERRUPT_STATES;
import static uk.gov.di.authentication.shared.helpers.WarmerHelper.isWarming;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.authentication.shared.state.StateMachine.userJourneyStateMachine;

public class AuthorisationHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthorisationHandler.class);

    private final SessionService sessionService;
    private final ConfigurationService configurationService;
    private final ClientSessionService clientSessionService;
    private final AuthorizationService authorizationService;
    private final AuditService auditService;
    private final StateMachine<SessionState, SessionAction, UserContext> stateMachine;

    public AuthorisationHandler(
            ConfigurationService configurationService,
            SessionService sessionService,
            ClientSessionService clientSessionService,
            AuthorizationService authorizationService,
            AuditService auditService,
            StateMachine<SessionState, SessionAction, UserContext> stateMachine) {
        this.configurationService = configurationService;
        this.sessionService = sessionService;
        this.clientSessionService = clientSessionService;
        this.authorizationService = authorizationService;
        this.auditService = auditService;
        this.stateMachine = stateMachine;
    }

    public AuthorisationHandler(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.sessionService = new SessionService(configurationService);
        this.clientSessionService = new ClientSessionService(configurationService);
        this.authorizationService = new AuthorizationService(configurationService);
        this.auditService = new AuditService();
        this.stateMachine = userJourneyStateMachine();
    }

    public AuthorisationHandler() {
        this(ConfigurationService.getInstance());
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return isWarming(input)
                .orElseGet(
                        () -> {
                            String ipAddress = IpAddressHelper.extractIpAddress(input);
                            auditService.submitAuditEvent(
                                    OidcAuditableEvent.AUTHORISATION_REQUEST_RECEIVED,
                                    context.getAwsRequestId(),
                                    AuditService.UNKNOWN,
                                    AuditService.UNKNOWN,
                                    AuditService.UNKNOWN,
                                    AuditService.UNKNOWN,
                                    ipAddress,
                                    AuditService.UNKNOWN);
                            LOGGER.info("Received authentication request");

                            Map<String, List<String>> queryStringParameters =
                                    getQueryStringParametersAsMap(input);
                            AuthenticationRequest authRequest;
                            try {
                                authRequest = AuthenticationRequest.parse(queryStringParameters);
                            } catch (ParseException e) {
                                if (e.getRedirectionURI() == null) {
                                    LOGGER.error(
                                            "Authentication request could not be parsed: redirect URI or Client ID is missing from auth request");
                                    // TODO - We need to come up with a strategy to handle uncaught
                                    // exceptions
                                    throw new RuntimeException(
                                            "Redirect URI or ClientID is missing from auth request",
                                            e);
                                }
                                LOGGER.error("Authentication request could not be parsed", e);
                                return generateErrorResponse(
                                        e.getRedirectionURI(),
                                        e.getState(),
                                        e.getResponseMode(),
                                        e.getErrorObject(),
                                        context,
                                        ipAddress);
                            }
                            Optional<ErrorObject> error =
                                    authorizationService.validateAuthRequest(authRequest);

                            return error.map(
                                            e ->
                                                    generateErrorResponse(
                                                            authRequest, e, context, ipAddress))
                                    .orElseGet(
                                            () ->
                                                    getOrCreateSessionAndRedirect(
                                                            queryStringParameters,
                                                            sessionService
                                                                    .getSessionFromSessionCookie(
                                                                            input.getHeaders()),
                                                            authRequest,
                                                            context,
                                                            ipAddress));
                        });
    }

    private APIGatewayProxyResponseEvent getOrCreateSessionAndRedirect(
            Map<String, List<String>> authRequestParameters,
            Optional<Session> existingSession,
            AuthenticationRequest authenticationRequest,
            Context context,
            String ipAddress) {
        final SessionAction sessionAction;
        if (authenticationRequest.getPrompt() != null) {
            if (authenticationRequest.getPrompt().contains(Prompt.Type.CONSENT)
                    || authenticationRequest.getPrompt().contains(Prompt.Type.SELECT_ACCOUNT)) {
                return generateErrorResponse(
                        authenticationRequest,
                        OIDCError.UNMET_AUTHENTICATION_REQUIREMENTS,
                        context,
                        ipAddress);
            }
            if (authenticationRequest.getPrompt().contains(Prompt.Type.NONE)
                    && !isUserAuthenticated(existingSession)) {
                return generateErrorResponse(
                        authenticationRequest, OIDCError.LOGIN_REQUIRED, context, ipAddress);
            }
            if (authenticationRequest.getPrompt().contains(Prompt.Type.LOGIN)
                    && isUserAuthenticated(existingSession)) {
                sessionAction = USER_HAS_STARTED_A_NEW_JOURNEY_WITH_LOGIN_REQUIRED;
            } else {
                sessionAction = USER_HAS_STARTED_A_NEW_JOURNEY;
            }
        } else {
            sessionAction = USER_HAS_STARTED_A_NEW_JOURNEY;
        }

        var session = existingSession.orElseGet(sessionService::createSession);

        auditService.submitAuditEvent(
                OidcAuditableEvent.AUTHORISATION_INITIATED,
                context.getAwsRequestId(),
                session.getSessionId(),
                authenticationRequest.getClientID().getValue(),
                AuditService.UNKNOWN,
                AuditService.UNKNOWN,
                ipAddress,
                AuditService.UNKNOWN,
                pair("session-action", sessionAction));

        if (existingSession.isEmpty()) {
            return createSessionAndRedirect(session, authRequestParameters, authenticationRequest);
        } else {
            return updateSessionAndRedirect(
                    authRequestParameters, authenticationRequest, session, sessionAction);
        }
    }

    private APIGatewayProxyResponseEvent updateSessionAndRedirect(
            Map<String, List<String>> authRequestParameters,
            AuthenticationRequest authenticationRequest,
            Session session,
            SessionAction sessionAction) {
        ClientSession clientSession =
                new ClientSession(
                        authRequestParameters,
                        LocalDateTime.now(),
                        authorizationService.getEffectiveVectorOfTrust(authenticationRequest));
        String clientSessionID = clientSessionService.generateClientSession(clientSession);
        UserContext userContext = authorizationService.buildUserContext(session, clientSession);
        SessionState nextState;
        try {
            nextState = stateMachine.transition(session.getState(), sessionAction, userContext);
        } catch (StateMachine.InvalidStateTransitionException e) {
            throw new RuntimeException(e);
        }

        session =
                updateSessionId(
                        session, authenticationRequest.getClientID(), clientSessionID, nextState);

        String redirectUri =
                buildRedirectURI(authRequestParameters, authenticationRequest, nextState);

        return redirect(session, clientSessionID, redirectUri);
    }

    private boolean isUserAuthenticated(Optional<Session> existingSession) {
        return existingSession
                .map(session -> session.getState().equals(SessionState.AUTHENTICATED))
                .orElse(Boolean.FALSE);
    }

    private Session updateSessionId(
            Session session, ClientID clientId, String clientSessionID, SessionState nextState) {
        String oldSessionId = session.getSessionId();
        sessionService.updateSessionId(session);
        session.addClientSession(clientSessionID);
        LOGGER.info(
                "Updated session id from {} to {} for client {} - client session id = {} - new",
                oldSessionId,
                session.getSessionId(),
                clientId.getValue(),
                clientSessionID);

        sessionService.save(session.setState(nextState));
        LOGGER.info("Session saved successfully {}", session.getSessionId());
        return session;
    }

    private APIGatewayProxyResponseEvent createSessionAndRedirect(
            Session session,
            Map<String, List<String>> authRequest,
            AuthenticationRequest authenticationRequest) {
        String clientSessionID =
                clientSessionService.generateClientSession(
                        new ClientSession(
                                authRequest,
                                LocalDateTime.now(),
                                authorizationService.getEffectiveVectorOfTrust(
                                        authenticationRequest)));
        session.addClientSession(clientSessionID);
        LOGGER.info(
                "Created session {} for client {} - client session id = {}",
                session.getSessionId(),
                authenticationRequest.getClientID().getValue(),
                clientSessionID);
        sessionService.save(session);
        LOGGER.info("Session saved successfully {}", session.getSessionId());

        var redirectURI = buildRedirectURI(authRequest, authenticationRequest, null);
        return redirect(session, clientSessionID, redirectURI);
    }

    private String buildRedirectURI(
            Map<String, List<String>> authRequestParameters,
            AuthenticationRequest authenticationRequest,
            SessionState nextState) {

        URI redirectUri;
        try {
            URIBuilder redirectUriBuilder = new URIBuilder(configurationService.getLoginURI());

            if (nextState != null && INTERRUPT_STATES.contains(nextState)) {
                redirectUriBuilder.addParameter("interrupt", nextState.toString());
            }

            String cookieConsent =
                    getCookieConsentValue(authRequestParameters, authenticationRequest);

            if (cookieConsent != null && !cookieConsent.isEmpty()) {
                redirectUriBuilder.addParameter(COOKIE_CONSENT, cookieConsent);
            }

            String gaValue = getGAUserIdValue(authRequestParameters);

            if (gaValue != null && !gaValue.isEmpty()) {
                redirectUriBuilder.addParameter(GA, gaValue);
            }

            redirectUri = redirectUriBuilder.build();
        } catch (URISyntaxException e) {
            throw new RuntimeException("Error constructing redirect URI", e);
        }

        return redirectUri.toString();
    }

    private APIGatewayProxyResponseEvent redirect(
            Session session, String clientSessionID, String redirectURI) {
        LOGGER.info(
                "Redirecting for SessionId: {} and ClientSessionId: {}",
                session.getSessionId(),
                clientSessionID);
        return new APIGatewayProxyResponseEvent()
                .withStatusCode(302)
                .withHeaders(
                        Map.of(
                                ResponseHeaders.LOCATION,
                                redirectURI,
                                ResponseHeaders.SET_COOKIE,
                                buildCookieString(
                                        session,
                                        configurationService.getSessionCookieMaxAge(),
                                        configurationService.getSessionCookieAttributes(),
                                        clientSessionID,
                                        configurationService.getDomainName())));
    }

    private APIGatewayProxyResponseEvent generateErrorResponse(
            AuthenticationRequest authRequest,
            ErrorObject errorObject,
            Context context,
            String ipAddress) {

        return generateErrorResponse(
                authRequest.getRedirectionURI(),
                authRequest.getState(),
                authRequest.getResponseMode(),
                errorObject,
                context,
                ipAddress);
    }

    private APIGatewayProxyResponseEvent generateErrorResponse(
            URI redirectUri,
            State state,
            ResponseMode responseMode,
            ErrorObject errorObject,
            Context context,
            String ipAddress) {

        auditService.submitAuditEvent(
                OidcAuditableEvent.AUTHORISATION_REQUEST_ERROR,
                context.getAwsRequestId(),
                AuditService.UNKNOWN,
                AuditService.UNKNOWN,
                AuditService.UNKNOWN,
                AuditService.UNKNOWN,
                ipAddress,
                AuditService.UNKNOWN,
                pair("description", errorObject.getDescription()));

        LOGGER.error(
                "Returning error response: {} {}",
                errorObject.getCode(),
                errorObject.getDescription());
        AuthenticationErrorResponse error =
                new AuthenticationErrorResponse(redirectUri, errorObject, state, responseMode);
        return new APIGatewayProxyResponseEvent()
                .withStatusCode(302)
                .withHeaders(Map.of(ResponseHeaders.LOCATION, error.toURI().toString()));
    }

    private Map<String, List<String>> getQueryStringParametersAsMap(
            APIGatewayProxyRequestEvent input) {
        return input.getQueryStringParameters().entrySet().stream()
                .collect(Collectors.toMap(Map.Entry::getKey, entry -> List.of(entry.getValue())));
    }

    private String buildCookieString(
            Session session,
            Integer maxAge,
            String attributes,
            String clientSessionID,
            String domain) {
        return format(
                "%s=%s.%s; Max-Age=%d; Domain=%s; %s",
                "gs", session.getSessionId(), clientSessionID, maxAge, domain, attributes);
    }

    private String getCookieConsentValue(
            Map<String, List<String>> authRequestParameters,
            AuthenticationRequest authenticationRequest) {

        if (authRequestParameters.containsKey(COOKIE_CONSENT)) {
            try {
                if (authorizationService.isClientCookieConsentShared(
                                authenticationRequest.getClientID())
                        && !authRequestParameters.get(COOKIE_CONSENT).isEmpty()) {
                    LOGGER.info(
                            "Sharing cookie_consent for client {}",
                            authenticationRequest.getClientID());

                    return authRequestParameters.get(COOKIE_CONSENT).get(0);
                }
            } catch (ClientNotFoundException e) {
                throw new RuntimeException("Client not found", e);
            }
        }

        return null;
    }

    private String getGAUserIdValue(Map<String, List<String>> authRequestParameters) {

        if (authRequestParameters.containsKey(GA)) {
            String gaId = authRequestParameters.get(GA).get(0);
            LOGGER.info("GA value present in request {}", gaId);

            return gaId;
        }

        return null;
    }
}

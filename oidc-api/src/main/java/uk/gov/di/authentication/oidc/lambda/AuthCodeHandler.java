package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.authentication.oidc.entity.ResponseHeaders;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.SessionAction;
import uk.gov.di.authentication.shared.entity.SessionState;
import uk.gov.di.authentication.shared.exceptions.ClientNotFoundException;
import uk.gov.di.authentication.shared.helpers.CookieHelper;
import uk.gov.di.authentication.shared.helpers.CookieHelper.SessionCookieIds;
import uk.gov.di.authentication.shared.services.AuthorisationCodeService;
import uk.gov.di.authentication.shared.services.AuthorizationService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.state.StateMachine;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;

import static uk.gov.di.authentication.shared.entity.SessionAction.SYSTEM_HAS_ISSUED_AUTHORIZATION_CODE;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.WarmerHelper.isWarming;
import static uk.gov.di.authentication.shared.state.StateMachine.userJourneyStateMachine;

public class AuthCodeHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final SessionService sessionService;
    private final AuthorisationCodeService authorisationCodeService;
    private final ConfigurationService configurationService;
    private final AuthorizationService authorizationService;
    private final ClientSessionService clientSessionService;
    private final StateMachine<SessionState, SessionAction, UserContext> stateMachine =
            userJourneyStateMachine();

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthCodeHandler.class);

    public AuthCodeHandler(
            SessionService sessionService,
            AuthorisationCodeService authorisationCodeService,
            ConfigurationService configurationService,
            AuthorizationService authorizationService,
            ClientSessionService clientSessionService) {
        this.sessionService = sessionService;
        this.authorisationCodeService = authorisationCodeService;
        this.configurationService = configurationService;
        this.authorizationService = authorizationService;
        this.clientSessionService = clientSessionService;
    }

    public AuthCodeHandler() {
        configurationService = new ConfigurationService();
        sessionService = new SessionService(configurationService);
        authorisationCodeService = new AuthorisationCodeService(configurationService);
        authorizationService = new AuthorizationService(configurationService);
        clientSessionService = new ClientSessionService(configurationService);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return isWarming(input)
                .orElseGet(
                        () -> {
                            SessionCookieIds sessionCookieIds;
                            Session session;
                            try {
                                sessionCookieIds =
                                        CookieHelper.parseSessionCookie(input.getHeaders())
                                                .orElseThrow();
                                session =
                                        sessionService
                                                .readSessionFromRedis(
                                                        sessionCookieIds.getSessionId())
                                                .orElseThrow();
                            } catch (NoSuchElementException e) {
                                LOGGER.error(
                                        "SessionID not there for INPUT: {}", input.getHeaders());
                                return generateApiGatewayProxyErrorResponse(
                                        400, ErrorResponse.ERROR_1000);
                            }

                            LOGGER.info(
                                    "AuthCodeHandler processing request for session {}",
                                    session.getSessionId());

                            SessionState nextState;
                            try {
                                nextState =
                                        stateMachine.transition(
                                                session.getState(),
                                                SYSTEM_HAS_ISSUED_AUTHORIZATION_CODE);
                            } catch (StateMachine.InvalidStateTransitionException e) {
                                LOGGER.error(
                                        "Invalid state transition for session {}",
                                        session.getSessionId());
                                return generateApiGatewayProxyErrorResponse(
                                        400, ErrorResponse.ERROR_1017);
                            }

                            AuthenticationRequest authenticationRequest;
                            try {
                                Map<String, List<String>> authRequest =
                                        clientSessionService
                                                .getClientSession(
                                                        sessionCookieIds.getClientSessionId())
                                                .getAuthRequestParams();
                                authenticationRequest = AuthenticationRequest.parse(authRequest);
                            } catch (ParseException e) {
                                if (e.getRedirectionURI() == null) {
                                    LOGGER.error(
                                            "Authentication request could not be parsed: redirect URI or Client ID is missing from auth request",
                                            e);
                                    // TODO - We need to come up with a strategy to handle uncaught
                                    // exceptions
                                    throw new RuntimeException(
                                            "Redirect URI or Client ID is missing from auth request",
                                            e);
                                }
                                LOGGER.error("Authentication request could not be parsed", e);
                                AuthenticationErrorResponse errorResponse =
                                        authorizationService.generateAuthenticationErrorResponse(
                                                e.getRedirectionURI(),
                                                e.getState(),
                                                e.getResponseMode(),
                                                e.getErrorObject());
                                return new APIGatewayProxyResponseEvent()
                                        .withStatusCode(302)
                                        .withHeaders(
                                                Map.of(
                                                        ResponseHeaders.LOCATION,
                                                        errorResponse.toURI().toString()));
                            }

                            try {
                                if (!authorizationService.isClientRedirectUriValid(
                                        authenticationRequest.getClientID(),
                                        authenticationRequest.getRedirectionURI())) {
                                    LOGGER.error(
                                            "Invalid client redirect URI ({}) for session {}",
                                            authenticationRequest.getRedirectionURI(),
                                            session.getSessionId());
                                    return generateApiGatewayProxyErrorResponse(
                                            400, ErrorResponse.ERROR_1016);
                                }
                            } catch (ClientNotFoundException e) {
                                AuthenticationErrorResponse errorResponse =
                                        authorizationService.generateAuthenticationErrorResponse(
                                                authenticationRequest, OAuth2Error.INVALID_CLIENT);
                                LOGGER.error(
                                        "Client not found for session {}", session.getSessionId());
                                return new APIGatewayProxyResponseEvent()
                                        .withStatusCode(302)
                                        .withHeaders(
                                                Map.of(
                                                        ResponseHeaders.LOCATION,
                                                        errorResponse.toURI().toString()));
                            }

                            AuthorizationCode authCode =
                                    authorisationCodeService.generateAuthorisationCode(
                                            sessionCookieIds.getClientSessionId(),
                                            session.getEmailAddress());
                            AuthenticationSuccessResponse authenticationResponse =
                                    authorizationService.generateSuccessfulAuthResponse(
                                            authenticationRequest, authCode);
                            sessionService.save(session.setState(nextState));
                            return new APIGatewayProxyResponseEvent()
                                    .withStatusCode(302)
                                    .withHeaders(
                                            Map.of(
                                                    ResponseHeaders.LOCATION,
                                                    authenticationResponse.toURI().toString()));
                        });
    }
}

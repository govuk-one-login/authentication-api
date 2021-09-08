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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.authentication.oidc.domain.OidcAuditableEvent;
import uk.gov.di.authentication.oidc.entity.ResponseHeaders;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.SessionState;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthorizationService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SessionService;

import java.net.URI;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import static java.lang.String.format;
import static software.amazon.awssdk.http.HttpStatusCode.OK;
import static uk.gov.di.authentication.shared.entity.SessionState.AUTHENTICATED;
import static uk.gov.di.authentication.shared.entity.SessionState.AUTHENTICATION_REQUIRED;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;

public class AuthorisationHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthorisationHandler.class);

    private final SessionService sessionService;
    private final ConfigurationService configurationService;
    private final ClientSessionService clientSessionService;
    private final AuthorizationService authorizationService;
    private final AuditService auditService;

    public AuthorisationHandler(
            ConfigurationService configurationService,
            SessionService sessionService,
            ClientSessionService clientSessionService,
            AuthorizationService authorizationService,
            AuditService auditService) {
        this.configurationService = configurationService;
        this.sessionService = sessionService;
        this.clientSessionService = clientSessionService;
        this.authorizationService = authorizationService;
        this.auditService = auditService;
    }

    public AuthorisationHandler() {
        configurationService = new ConfigurationService();
        this.sessionService = new SessionService(configurationService);
        this.clientSessionService = new ClientSessionService(configurationService);
        this.authorizationService = new AuthorizationService(configurationService);
        this.auditService = new AuditService();
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        LOGGER.info("Input is {}", input.toString());
        if (input == null)
            return new APIGatewayProxyResponseEvent().withBody("I'm warm").withStatusCode(OK);

        auditService.submitAuditEvent(OidcAuditableEvent.AUTHORISATION_REQUEST_RECEIVED);
        LOGGER.info("Received authentication request");

        Map<String, List<String>> queryStringParameters = getQueryStringParametersAsMap(input);
        AuthenticationRequest authRequest;
        try {
            authRequest = AuthenticationRequest.parse(queryStringParameters);
        } catch (ParseException e) {
            if (e.getRedirectionURI() == null) {
                LOGGER.error(
                        "Authentication request could not be parsed: redirect URI or Client ID is missing from auth request");
                // TODO - We need to come up with a strategy to handle uncaught exceptions
                throw new RuntimeException(
                        "Redirect URI or ClientID is missing from auth request", e);
            }
            LOGGER.error("Authentication request could not be parsed", e);
            return generateErrorResponse(
                    e.getRedirectionURI(), e.getState(), e.getResponseMode(), e.getErrorObject());
        }
        Optional<ErrorObject> error = authorizationService.validateAuthRequest(authRequest);

        return error.map(e -> generateErrorResponse(authRequest, e))
                .orElseGet(
                        () ->
                                getOrCreateSessionAndRedirect(
                                        queryStringParameters,
                                        sessionService.getSessionFromSessionCookie(
                                                input.getHeaders()),
                                        authRequest));
    }

    private APIGatewayProxyResponseEvent getOrCreateSessionAndRedirect(
            Map<String, List<String>> authRequestParameters,
            Optional<Session> existingSession,
            AuthenticationRequest authenticationRequest) {
        if (authenticationRequest.getPrompt() != null) {
            if (authenticationRequest.getPrompt().contains(Prompt.Type.CONSENT)
                    || authenticationRequest.getPrompt().contains(Prompt.Type.SELECT_ACCOUNT)) {
                return generateErrorResponse(
                        authenticationRequest, OIDCError.UNMET_AUTHENTICATION_REQUIREMENTS);
            }
            if (authenticationRequest.getPrompt().contains(Prompt.Type.NONE)
                    && !isUserAuthenticated(existingSession)) {
                return generateErrorResponse(authenticationRequest, OIDCError.LOGIN_REQUIRED);
            }
            if (authenticationRequest.getPrompt().contains(Prompt.Type.LOGIN)
                    && isUserAuthenticated(existingSession)) {
                existingSession.ifPresent(session -> session.setState(AUTHENTICATION_REQUIRED));
            }
        }

        return existingSession
                .map(
                        session -> {
                            URI redirectUri = configurationService.getAuthCodeURI();
                            if (!session.getState().equals(AUTHENTICATED)) {
                                redirectUri = configurationService.getLoginURI();
                            }
                            return updateSessionAndRedirect(
                                    authRequestParameters,
                                    authenticationRequest,
                                    session,
                                    redirectUri);
                        })
                .orElseGet(
                        () ->
                                createSessionAndRedirect(
                                        authRequestParameters,
                                        authenticationRequest.getClientID(),
                                        configurationService.getLoginURI()));
    }

    private APIGatewayProxyResponseEvent updateSessionAndRedirect(
            Map<String, List<String>> authRequestParameters,
            AuthenticationRequest authenticationRequest,
            Session session,
            URI redirectURI) {
        String clientSessionID =
                clientSessionService.generateClientSession(
                        new ClientSession(authRequestParameters, LocalDateTime.now()));
        updateSessionId(session, authenticationRequest.getClientID(), clientSessionID);
        return redirect(session, clientSessionID, redirectURI);
    }

    private boolean isUserAuthenticated(Optional<Session> existingSession) {
        return existingSession
                .map(session -> session.getState().equals(SessionState.AUTHENTICATED))
                .orElse(Boolean.FALSE);
    }

    private void updateSessionId(Session session, ClientID clientId, String clientSessionID) {
        String oldSessionId = session.getSessionId();
        sessionService.updateSessionId(session);
        session.addClientSession(clientSessionID);
        LOGGER.info(
                "Updated session id from {} to {} for client {} - client session id = {}",
                oldSessionId,
                session.getSessionId(),
                clientId.getValue(),
                clientSessionID);

        sessionService.save(session);
        LOGGER.info("Session saved successfully {}", session.getSessionId());
    }

    private APIGatewayProxyResponseEvent createSessionAndRedirect(
            Map<String, List<String>> authRequest, ClientID clientId, URI redirectURI) {
        Session session = sessionService.createSession();

        String clientSessionID =
                clientSessionService.generateClientSession(
                        new ClientSession(authRequest, LocalDateTime.now()));
        session.addClientSession(clientSessionID);
        LOGGER.info(
                "Created session {} for client {} - client session id = {}",
                session.getSessionId(),
                clientId.getValue(),
                clientSessionID);
        sessionService.save(session);
        LOGGER.info("Session saved successfully {}", session.getSessionId());
        return redirect(session, clientSessionID, redirectURI);
    }

    private APIGatewayProxyResponseEvent redirect(
            Session session, String clientSessionID, URI redirectURI) {
        return new APIGatewayProxyResponseEvent()
                .withStatusCode(302)
                .withHeaders(
                        Map.of(
                                ResponseHeaders.LOCATION,
                                redirectURI.toString(),
                                ResponseHeaders.SET_COOKIE,
                                buildCookieString(
                                        session,
                                        configurationService.getSessionCookieMaxAge(),
                                        configurationService.getSessionCookieAttributes(),
                                        clientSessionID,
                                        configurationService.getDomainName())));
    }

    private APIGatewayProxyResponseEvent generateErrorResponse(
            AuthenticationRequest authRequest, ErrorObject errorObject) {

        return generateErrorResponse(
                authRequest.getRedirectionURI(),
                authRequest.getState(),
                authRequest.getResponseMode(),
                errorObject);
    }

    private APIGatewayProxyResponseEvent generateErrorResponse(
            URI redirectUri, State state, ResponseMode responseMode, ErrorObject errorObject) {

        auditService.submitAuditEvent(
                OidcAuditableEvent.AUTHORISATION_REQUEST_ERROR,
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
}

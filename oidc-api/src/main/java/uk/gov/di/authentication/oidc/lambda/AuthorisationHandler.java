package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.OIDCError;
import com.nimbusds.openid.connect.sdk.Prompt;
import org.apache.http.client.utils.URIBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.oidc.domain.OidcAuditableEvent;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.ResponseHeaders;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.exceptions.ClientNotFoundException;
import uk.gov.di.authentication.shared.helpers.CookieHelper;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthorizationService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SessionService;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

import static uk.gov.di.authentication.oidc.entity.RequestParameters.COOKIE_CONSENT;
import static uk.gov.di.authentication.oidc.entity.RequestParameters.GA;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.AWS_REQUEST_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.CLIENT_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.CLIENT_SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.PERSISTENT_SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachSessionIdToLogs;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.updateAttachedLogFieldToLogs;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.updateAttachedSessionIdToLogs;
import static uk.gov.di.authentication.shared.helpers.WarmerHelper.isWarming;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;

public class AuthorisationHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(AuthorisationHandler.class);

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

    public AuthorisationHandler(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.sessionService = new SessionService(configurationService);
        this.clientSessionService = new ClientSessionService(configurationService);
        this.authorizationService = new AuthorizationService(configurationService);
        this.auditService = new AuditService(configurationService);
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
                            String persistentSessionId =
                                    authorizationService.getExistingOrCreateNewPersistentSessionId(
                                            input.getHeaders());
                            String ipAddress = IpAddressHelper.extractIpAddress(input);
                            auditService.submitAuditEvent(
                                    OidcAuditableEvent.AUTHORISATION_REQUEST_RECEIVED,
                                    context.getAwsRequestId(),
                                    AuditService.UNKNOWN,
                                    AuditService.UNKNOWN,
                                    AuditService.UNKNOWN,
                                    AuditService.UNKNOWN,
                                    ipAddress,
                                    AuditService.UNKNOWN,
                                    persistentSessionId);
                            attachLogFieldToLogs(PERSISTENT_SESSION_ID, persistentSessionId);
                            attachLogFieldToLogs(AWS_REQUEST_ID, context.getAwsRequestId());
                            LOG.info("Received authentication request");

                            Map<String, List<String>> queryStringParameters;
                            AuthenticationRequest authRequest;
                            try {
                                queryStringParameters = getQueryStringParametersAsMap(input);
                                authRequest = AuthenticationRequest.parse(queryStringParameters);
                            } catch (ParseException e) {
                                if (e.getRedirectionURI() == null) {
                                    LOG.warn(
                                            "Authentication request could not be parsed: redirect URI or Client ID is missing from auth request");
                                    throw new RuntimeException(
                                            "Redirect URI or ClientID is missing from auth request",
                                            e);
                                }
                                LOG.warn("Authentication request could not be parsed", e);
                                return generateErrorResponse(
                                        e.getRedirectionURI(),
                                        e.getState(),
                                        e.getResponseMode(),
                                        e.getErrorObject(),
                                        context,
                                        ipAddress,
                                        persistentSessionId);
                            } catch (NullPointerException e) {
                                LOG.warn(
                                        "No query string parameters are present in the Authentication request",
                                        e);
                                throw new RuntimeException(
                                        "No query string parameters are present in the Authentication request",
                                        e);
                            }
                            Optional<ErrorObject> error =
                                    authorizationService.validateAuthRequest(authRequest);

                            return error.map(
                                            e ->
                                                    generateErrorResponse(
                                                            authRequest.getRedirectionURI(),
                                                            authRequest.getState(),
                                                            authRequest.getResponseMode(),
                                                            e,
                                                            context,
                                                            ipAddress,
                                                            persistentSessionId))
                                    .orElseGet(
                                            () ->
                                                    getOrCreateSessionAndRedirect(
                                                            queryStringParameters,
                                                            sessionService
                                                                    .getSessionFromSessionCookie(
                                                                            input.getHeaders()),
                                                            authRequest,
                                                            context,
                                                            ipAddress,
                                                            persistentSessionId));
                        });
    }

    private APIGatewayProxyResponseEvent getOrCreateSessionAndRedirect(
            Map<String, List<String>> authRequestParameters,
            Optional<Session> existingSession,
            AuthenticationRequest authenticationRequest,
            Context context,
            String ipAddress,
            String persistentSessionId) {
        if (Objects.nonNull(authenticationRequest.getPrompt())) {
            if (authenticationRequest.getPrompt().contains(Prompt.Type.CONSENT)
                    || authenticationRequest.getPrompt().contains(Prompt.Type.SELECT_ACCOUNT)) {
                return generateErrorResponse(
                        authenticationRequest.getRedirectionURI(),
                        authenticationRequest.getState(),
                        authenticationRequest.getResponseMode(),
                        OIDCError.UNMET_AUTHENTICATION_REQUIREMENTS,
                        context,
                        ipAddress,
                        persistentSessionId);
            }
        }

        var session = existingSession.orElseGet(sessionService::createSession);

        attachSessionIdToLogs(session);

        auditService.submitAuditEvent(
                OidcAuditableEvent.AUTHORISATION_INITIATED,
                context.getAwsRequestId(),
                session.getSessionId(),
                authenticationRequest.getClientID().getValue(),
                AuditService.UNKNOWN,
                AuditService.UNKNOWN,
                ipAddress,
                AuditService.UNKNOWN,
                persistentSessionId);

        if (existingSession.isEmpty()) {
            return createSessionAndRedirect(
                    session, authRequestParameters, authenticationRequest, persistentSessionId);
        } else {
            return updateSessionAndRedirect(
                    authRequestParameters, authenticationRequest, session, persistentSessionId);
        }
    }

    private APIGatewayProxyResponseEvent updateSessionAndRedirect(
            Map<String, List<String>> authRequestParameters,
            AuthenticationRequest authenticationRequest,
            Session session,
            String persistentSessionId) {
        ClientSession clientSession =
                new ClientSession(
                        authRequestParameters,
                        LocalDateTime.now(),
                        authorizationService.getEffectiveVectorOfTrust(authenticationRequest));
        String clientSessionID = clientSessionService.generateClientSession(clientSession);
        String oldSessionId = session.getSessionId();
        sessionService.updateSessionId(session);
        session.addClientSession(clientSessionID);
        updateAttachedSessionIdToLogs(session.getSessionId());
        updateAttachedLogFieldToLogs(CLIENT_SESSION_ID, clientSessionID);
        LOG.info("Updated session id from {} - new", oldSessionId);

        sessionService.save(session);
        LOG.info("Session saved successfully");

        String redirectUri = buildRedirectURI(authRequestParameters, authenticationRequest);

        return redirect(session, clientSessionID, redirectUri, persistentSessionId);
    }

    private APIGatewayProxyResponseEvent createSessionAndRedirect(
            Session session,
            Map<String, List<String>> authRequest,
            AuthenticationRequest authenticationRequest,
            String persistentSessionId) {
        String clientSessionID =
                clientSessionService.generateClientSession(
                        new ClientSession(
                                authRequest,
                                LocalDateTime.now(),
                                authorizationService.getEffectiveVectorOfTrust(
                                        authenticationRequest)));
        session.addClientSession(clientSessionID);
        updateAttachedSessionIdToLogs(session.getSessionId());
        updateAttachedLogFieldToLogs(CLIENT_SESSION_ID, clientSessionID);
        updateAttachedLogFieldToLogs(CLIENT_ID, authenticationRequest.getClientID().getValue());
        LOG.info("Created session");
        sessionService.save(session);
        LOG.info("Session saved successfully");

        var redirectURI = buildRedirectURI(authRequest, authenticationRequest);
        return redirect(session, clientSessionID, redirectURI, persistentSessionId);
    }

    private String buildRedirectURI(
            Map<String, List<String>> authRequestParameters,
            AuthenticationRequest authenticationRequest) {

        URI redirectUri;
        try {
            URIBuilder redirectUriBuilder = new URIBuilder(configurationService.getLoginURI());

            if (Objects.nonNull(authenticationRequest.getPrompt())
                    && authenticationRequest.getPrompt().contains(Prompt.Type.LOGIN)) {
                redirectUriBuilder.addParameter("prompt", String.valueOf(Prompt.Type.LOGIN));
            }

            var cookieConsent = getCookieConsentValue(authRequestParameters, authenticationRequest);
            cookieConsent.ifPresent(c -> redirectUriBuilder.addParameter(COOKIE_CONSENT, c));

            var gaValue = getGAUserIdValue(authRequestParameters);
            gaValue.ifPresent(ga -> redirectUriBuilder.addParameter(GA, ga));

            redirectUri = redirectUriBuilder.build();
        } catch (URISyntaxException e) {
            throw new RuntimeException("Error constructing redirect URI", e);
        }
        return redirectUri.toString();
    }

    private APIGatewayProxyResponseEvent redirect(
            Session session,
            String clientSessionID,
            String redirectURI,
            String persistentSessionId) {
        LOG.info("Redirecting");
        List<String> cookies =
                List.of(
                        CookieHelper.buildCookieString(
                                CookieHelper.SESSION_COOKIE_NAME,
                                session.getSessionId() + "." + clientSessionID,
                                configurationService.getSessionCookieMaxAge(),
                                configurationService.getSessionCookieAttributes(),
                                configurationService.getDomainName()),
                        CookieHelper.buildCookieString(
                                CookieHelper.PERSISTENT_COOKIE_NAME,
                                persistentSessionId,
                                configurationService.getPersistentCookieMaxAge(),
                                configurationService.getSessionCookieAttributes(),
                                configurationService.getDomainName()));
        return new APIGatewayProxyResponseEvent()
                .withStatusCode(302)
                .withHeaders(Map.of(ResponseHeaders.LOCATION, redirectURI))
                .withMultiValueHeaders(Map.of(ResponseHeaders.SET_COOKIE, cookies));
    }

    private APIGatewayProxyResponseEvent generateErrorResponse(
            URI redirectUri,
            State state,
            ResponseMode responseMode,
            ErrorObject errorObject,
            Context context,
            String ipAddress,
            String persistentSessionId) {

        auditService.submitAuditEvent(
                OidcAuditableEvent.AUTHORISATION_REQUEST_ERROR,
                context.getAwsRequestId(),
                AuditService.UNKNOWN,
                AuditService.UNKNOWN,
                AuditService.UNKNOWN,
                AuditService.UNKNOWN,
                ipAddress,
                AuditService.UNKNOWN,
                persistentSessionId,
                pair("description", errorObject.getDescription()));

        LOG.warn(
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

    private Optional<String> getCookieConsentValue(
            Map<String, List<String>> authRequestParameters,
            AuthenticationRequest authenticationRequest) {

        if (authRequestParameters.containsKey(COOKIE_CONSENT)) {
            try {
                if (authorizationService.isClientCookieConsentShared(
                                authenticationRequest.getClientID())
                        && !authRequestParameters.get(COOKIE_CONSENT).isEmpty()
                        && authorizationService.isValidCookieConsentValue(
                                authRequestParameters.get(COOKIE_CONSENT).get(0))) {
                    LOG.info("Sharing cookie_consent");
                    return Optional.of(authRequestParameters.get(COOKIE_CONSENT).get(0));
                }
            } catch (ClientNotFoundException e) {
                throw new RuntimeException("Client not found", e);
            }
        }

        return Optional.empty();
    }

    private Optional<String> getGAUserIdValue(Map<String, List<String>> authRequestParameters) {
        if (authRequestParameters.containsKey(GA)) {
            String gaId = authRequestParameters.get(GA).get(0);
            LOG.info("GA value present in request {}", gaId);
            return Optional.of(gaId);
        }
        return Optional.empty();
    }
}

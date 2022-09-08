package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import org.apache.http.client.utils.URIBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.oidc.domain.OidcAuditableEvent;
import uk.gov.di.authentication.oidc.services.BackChannelLogoutService;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ResponseHeaders;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.helpers.CookieHelper;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoClientService;
import uk.gov.di.authentication.shared.services.JwksService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.services.TokenValidationService;

import java.net.URI;
import java.net.URISyntaxException;
import java.text.ParseException;
import java.util.Map;
import java.util.Optional;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.CLIENT_SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachSessionIdToLogs;
import static uk.gov.di.authentication.shared.helpers.WarmerHelper.isWarming;

public class LogoutHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(LogoutHandler.class);

    private final ConfigurationService configurationService;
    private final SessionService sessionService;
    private final DynamoClientService dynamoClientService;
    private final ClientSessionService clientSessionService;
    private final TokenValidationService tokenValidationService;
    private final AuditService auditService;
    private final BackChannelLogoutService backChannelLogoutService;
    private final CookieHelper cookieHelper;

    public LogoutHandler() {
        this(ConfigurationService.getInstance());
    }

    public LogoutHandler(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.sessionService = new SessionService(configurationService);
        this.dynamoClientService = new DynamoClientService(configurationService);
        this.clientSessionService = new ClientSessionService(configurationService);
        this.tokenValidationService =
                new TokenValidationService(
                        new JwksService(
                                configurationService,
                                new KmsConnectionService(configurationService)));
        this.auditService = new AuditService(configurationService);
        this.backChannelLogoutService = new BackChannelLogoutService(configurationService);
        this.cookieHelper = new CookieHelper();
    }

    public LogoutHandler(
            ConfigurationService configurationService,
            SessionService sessionService,
            DynamoClientService dynamoClientService,
            ClientSessionService clientSessionService,
            TokenValidationService tokenValidationService,
            AuditService auditService,
            BackChannelLogoutService backChannelLogoutService) {
        this.configurationService = configurationService;
        this.sessionService = sessionService;
        this.dynamoClientService = dynamoClientService;
        this.clientSessionService = clientSessionService;
        this.tokenValidationService = tokenValidationService;
        this.auditService = auditService;
        this.backChannelLogoutService = backChannelLogoutService;
        this.cookieHelper = new CookieHelper();
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return segmentedFunctionCall(
                "oidc-api::" + getClass().getSimpleName(),
                () -> logoutRequestHandler(input, context));
    }

    public APIGatewayProxyResponseEvent logoutRequestHandler(
            APIGatewayProxyRequestEvent input, Context context) {
        return isWarming(input)
                .orElseGet(
                        () -> {
                            LOG.info("Logout request received");
                            Optional<String> state;
                            if (input.getQueryStringParameters() == null
                                    || input.getQueryStringParameters().isEmpty()) {
                                LOG.info("No query string parameters in request");
                                state = Optional.empty();
                            } else {
                                state =
                                        Optional.ofNullable(
                                                input.getQueryStringParameters().get("state"));
                            }
                            Optional<Session> sessionFromSessionCookie =
                                    segmentedFunctionCall(
                                            "getSessionFromSessionCookie",
                                            () ->
                                                    sessionService.getSessionFromSessionCookie(
                                                            input.getHeaders()));
                            if (sessionFromSessionCookie.isPresent()) {
                                return segmentedFunctionCall(
                                        "processLogoutRequest",
                                        () ->
                                                processLogoutRequest(
                                                        sessionFromSessionCookie.get(),
                                                        input,
                                                        state,
                                                        context));
                            } else {
                                return segmentedFunctionCall(
                                        "generateDefaultLogoutResponse",
                                        () ->
                                                generateDefaultLogoutResponse(
                                                        state,
                                                        input,
                                                        context,
                                                        Optional.empty(),
                                                        Optional.empty()));
                            }
                        });
    }

    private APIGatewayProxyResponseEvent processLogoutRequest(
            Session session,
            APIGatewayProxyRequestEvent input,
            Optional<String> state,
            Context context) {

        CookieHelper.SessionCookieIds sessionCookieIds =
                cookieHelper.parseSessionCookie(input.getHeaders()).orElseThrow();

        attachSessionIdToLogs(session);
        attachLogFieldToLogs(CLIENT_SESSION_ID, sessionCookieIds.getClientSessionId());

        LOG.info("LogoutHandler processing request");

        if (!session.getClientSessions().contains(sessionCookieIds.getClientSessionId())) {
            LOG.warn("Client Session ID does not exist");
            return generateErrorLogoutResponse(
                    Optional.empty(),
                    new ErrorObject(OAuth2Error.INVALID_REQUEST_CODE, "invalid session"),
                    input,
                    context,
                    Optional.empty(),
                    Optional.of(session.getSessionId()));
        }

        Map<String, String> queryStringParameters = input.getQueryStringParameters();
        if (queryStringParameters == null || queryStringParameters.isEmpty()) {
            LOG.info("Deleting session and returning default logout as no input parameters");
            segmentedFunctionCall("destroySessions", () -> destroySessions(session));
            return generateDefaultLogoutResponse(
                    state, input, context, Optional.empty(), Optional.of(session.getSessionId()));
        }

        Optional<String> idTokenHint =
                Optional.ofNullable(queryStringParameters.get("id_token_hint"));
        Optional<String> postLogoutRedirectUri =
                Optional.ofNullable(queryStringParameters.get("post_logout_redirect_uri"));
        Optional<String> audience = Optional.empty();

        if (idTokenHint.isPresent()) {
            LOG.info("ID token hint is present");
            if (!doesIDTokenExistInSession(idTokenHint.get(), session)) {
                LOG.warn("ID token does not exist");
                return generateErrorLogoutResponse(
                        Optional.empty(),
                        new ErrorObject(
                                OAuth2Error.INVALID_REQUEST_CODE,
                                "unable to validate id_token_hint"),
                        input,
                        context,
                        Optional.empty(),
                        Optional.of(session.getSessionId()));
            }
            boolean isTokenSignatureValid =
                    segmentedFunctionCall(
                            "isTokenSignatureValid",
                            () -> tokenValidationService.isTokenSignatureValid(idTokenHint.get()));
            if (!isTokenSignatureValid) {
                LOG.warn("Unable to validate ID token signature");
                return generateErrorLogoutResponse(
                        Optional.empty(),
                        new ErrorObject(
                                OAuth2Error.INVALID_REQUEST_CODE,
                                "unable to validate id_token_hint"),
                        input,
                        context,
                        Optional.empty(),
                        Optional.of(session.getSessionId()));
            }

            try {
                SignedJWT idToken = SignedJWT.parse(idTokenHint.get());
                audience = idToken.getJWTClaimsSet().getAudience().stream().findFirst();
            } catch (ParseException e) {
                LOG.warn("Unable to parse id_token_hint into SignedJWT");
                return generateErrorLogoutResponse(
                        Optional.empty(),
                        new ErrorObject(OAuth2Error.INVALID_REQUEST_CODE, "invalid id_token_hint"),
                        input,
                        context,
                        Optional.empty(),
                        Optional.of(session.getSessionId()));
            }
        }
        segmentedFunctionCall("destroySessions", () -> destroySessions(session));
        if (audience.isPresent()) {
            final String finalAudience = audience.get();
            return segmentedFunctionCall(
                    "validateClientIDAgainstClientRegistry",
                    () ->
                            validateClientIDAgainstClientRegistry(
                                    postLogoutRedirectUri,
                                    finalAudience,
                                    state,
                                    input,
                                    context,
                                    Optional.of(session.getSessionId())));
        } else {
            return generateDefaultLogoutResponse(
                    state, input, context, audience, Optional.of(session.getSessionId()));
        }
    }

    private APIGatewayProxyResponseEvent validateClientIDAgainstClientRegistry(
            Optional<String> postLogoutRedirectUri,
            String clientID,
            Optional<String> state,
            APIGatewayProxyRequestEvent input,
            Context context,
            Optional<String> sessionId) {
        LOG.info("Validating ClientID");
        Optional<ClientRegistry> clientRegistry = dynamoClientService.getClient(clientID);
        if (clientRegistry.isEmpty()) {
            LOG.warn("Client not found in ClientRegistry");
            return generateErrorLogoutResponse(
                    state,
                    new ErrorObject(OAuth2Error.UNAUTHORIZED_CLIENT_CODE, "client not found"),
                    input,
                    context,
                    Optional.of(clientID),
                    sessionId);
        }

        return postLogoutRedirectUri
                .map(
                        uri -> {
                            if (!clientRegistry.get().getPostLogoutRedirectUrls().contains(uri)) {
                                LOG.warn(
                                        "Client registry does not contain PostLogoutRedirectUri which was sent in the logout request. Value is {}",
                                        uri);
                                return generateErrorLogoutResponse(
                                        state,
                                        new ErrorObject(
                                                OAuth2Error.INVALID_REQUEST_CODE,
                                                "client registry does not contain post_logout_redirect_uri"),
                                        input,
                                        context,
                                        Optional.of(clientID),
                                        sessionId);
                            } else {
                                LOG.info(
                                        "The post_logout_redirect_uri is present in logout request and client registry. Value is {}",
                                        uri);
                                return generateLogoutResponse(
                                        URI.create(uri),
                                        state,
                                        Optional.empty(),
                                        input,
                                        context,
                                        Optional.of(clientID),
                                        sessionId);
                            }
                        })
                .orElseGet(
                        () -> {
                            LOG.info(
                                    "post_logout_redirect_uri is NOT present in logout request. Generating default logout response");
                            return generateDefaultLogoutResponse(
                                    state, input, context, Optional.of(clientID), sessionId);
                        });
    }

    private APIGatewayProxyResponseEvent generateDefaultLogoutResponse(
            Optional<String> state,
            APIGatewayProxyRequestEvent input,
            Context context,
            Optional<String> clientId,
            Optional<String> sessionId) {
        LOG.info("Generating default Logout Response");
        return generateLogoutResponse(
                configurationService.getDefaultLogoutURI(),
                state,
                Optional.empty(),
                input,
                context,
                clientId,
                sessionId);
    }

    private APIGatewayProxyResponseEvent generateErrorLogoutResponse(
            Optional<String> state,
            ErrorObject errorObject,
            APIGatewayProxyRequestEvent input,
            Context context,
            Optional<String> clientId,
            Optional<String> sessionId) {
        LOG.info(
                "Generating Logout Error Response with code: {} and description: {}",
                errorObject.getCode(),
                errorObject.getDescription());
        return generateLogoutResponse(
                configurationService.getDefaultLogoutURI(),
                state,
                Optional.of(errorObject),
                input,
                context,
                clientId,
                sessionId);
    }

    private APIGatewayProxyResponseEvent generateLogoutResponse(
            URI logoutUri,
            Optional<String> state,
            Optional<ErrorObject> errorObject,
            APIGatewayProxyRequestEvent input,
            Context context,
            Optional<String> clientId,
            Optional<String> sessionId) {
        LOG.info("Generating Logout Response using URI: {}", logoutUri);
        URIBuilder uriBuilder = new URIBuilder(logoutUri);
        state.ifPresent(s -> uriBuilder.addParameter("state", s));
        errorObject.ifPresent(e -> uriBuilder.addParameter("error_code", e.getCode()));
        errorObject.ifPresent(
                e -> uriBuilder.addParameter("error_description", e.getDescription()));
        URI uri;
        try {
            uri = uriBuilder.build();
        } catch (URISyntaxException e) {
            LOG.error("Unable to generate logout response", e);
            throw new RuntimeException("Unable to build URI");
        }
        auditService.submitAuditEvent(
                OidcAuditableEvent.LOG_OUT_SUCCESS,
                AuditService.UNKNOWN,
                sessionId.orElse(AuditService.UNKNOWN),
                clientId.orElse(AuditService.UNKNOWN),
                AuditService.UNKNOWN,
                AuditService.UNKNOWN,
                IpAddressHelper.extractIpAddress(input),
                AuditService.UNKNOWN,
                PersistentIdHelper.extractPersistentIdFromCookieHeader(input.getHeaders()));

        return generateApiGatewayProxyResponse(
                302, "", Map.of(ResponseHeaders.LOCATION, uri.toString()), null);
    }

    private void destroySessions(Session session) {
        for (String clientSessionId : session.getClientSessions()) {
            clientSessionService
                    .getClientSession(clientSessionId)
                    .flatMap(
                            t ->
                                    t.getAuthRequestParams().get("client_id").stream()
                                            .findFirst()
                                            .flatMap(dynamoClientService::getClient))
                    .ifPresent(
                            clientRegistry ->
                                    backChannelLogoutService.sendLogoutMessage(
                                            clientRegistry, session.getEmailAddress()));
            LOG.info("Deleting Client Session");
            clientSessionService.deleteClientSessionFromRedis(clientSessionId);
        }
        LOG.info("Deleting Session");
        sessionService.deleteSessionFromRedis(session.getSessionId());
    }

    private boolean doesIDTokenExistInSession(String idTokenHint, Session session) {
        return session.getClientSessions().stream()
                .map(clientSessionService::getClientSession)
                .flatMap(Optional::stream)
                .anyMatch(cs -> idTokenHint.equals(cs.getIdTokenHint()));
    }
}

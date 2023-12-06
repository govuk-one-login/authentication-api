package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.authentication.oidc.services.LogoutService;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.Session;
import uk.gov.di.orchestration.shared.helpers.CookieHelper;
import uk.gov.di.orchestration.shared.services.ClientSessionService;
import uk.gov.di.orchestration.shared.services.CloudwatchMetricsService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.DynamoClientService;
import uk.gov.di.orchestration.shared.services.JwksService;
import uk.gov.di.orchestration.shared.services.KmsConnectionService;
import uk.gov.di.orchestration.shared.services.SessionService;
import uk.gov.di.orchestration.shared.services.TokenValidationService;

import java.net.URI;
import java.text.ParseException;
import java.util.Map;
import java.util.Optional;

import static uk.gov.di.orchestration.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.CLIENT_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.CLIENT_SESSION_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.GOVUK_SIGNIN_JOURNEY_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachSessionIdToLogs;

public class LogoutHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(LogoutHandler.class);

    private final SessionService sessionService;
    private final DynamoClientService dynamoClientService;
    private final ClientSessionService clientSessionService;
    private final TokenValidationService tokenValidationService;
    private final CloudwatchMetricsService cloudwatchMetricsService;
    private final CookieHelper cookieHelper;

    private final LogoutService logoutService;

    public LogoutHandler() {
        this(ConfigurationService.getInstance());
    }

    public LogoutHandler(ConfigurationService configurationService) {
        this.sessionService = new SessionService(configurationService);
        this.dynamoClientService = new DynamoClientService(configurationService);
        this.clientSessionService = new ClientSessionService(configurationService);
        this.tokenValidationService =
                new TokenValidationService(
                        new JwksService(
                                configurationService,
                                new KmsConnectionService(configurationService)),
                        configurationService);
        this.cloudwatchMetricsService = new CloudwatchMetricsService();
        this.cookieHelper = new CookieHelper();
        this.logoutService = new LogoutService(configurationService);
    }

    public LogoutHandler(
            SessionService sessionService,
            DynamoClientService dynamoClientService,
            ClientSessionService clientSessionService,
            TokenValidationService tokenValidationService,
            CloudwatchMetricsService cloudwatchMetricsService,
            LogoutService logoutService) {
        this.sessionService = sessionService;
        this.dynamoClientService = dynamoClientService;
        this.clientSessionService = clientSessionService;
        this.tokenValidationService = tokenValidationService;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
        this.cookieHelper = new CookieHelper();
        this.logoutService = logoutService;
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        ThreadContext.clearMap();
        return segmentedFunctionCall(
                "oidc-api::" + getClass().getSimpleName(),
                () -> logoutRequestHandler(input, context));
    }

    public APIGatewayProxyResponseEvent logoutRequestHandler(
            APIGatewayProxyRequestEvent input, Context context) {
        LOG.info("Logout request received");
        Optional<String> state;
        if (input.getQueryStringParameters() == null
                || input.getQueryStringParameters().isEmpty()) {
            LOG.info("No query string parameters in request");
            state = Optional.empty();
        } else {
            state = Optional.ofNullable(input.getQueryStringParameters().get("state"));
        }
        Optional<Session> sessionFromSessionCookie =
                segmentedFunctionCall(
                        "getSessionFromSessionCookie",
                        () -> sessionService.getSessionFromSessionCookie(input.getHeaders()));
        if (sessionFromSessionCookie.isPresent()) {
            return segmentedFunctionCall(
                    "processLogoutRequest",
                    () ->
                            processLogoutRequest(
                                    sessionFromSessionCookie.get(), input, state, context));
        } else {
            return segmentedFunctionCall(
                    "generateDefaultLogoutResponse",
                    () ->
                            logoutService.generateDefaultLogoutResponse(
                                    state, input, Optional.empty(), Optional.empty()));
        }
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
        attachLogFieldToLogs(GOVUK_SIGNIN_JOURNEY_ID, sessionCookieIds.getClientSessionId());

        LOG.info("LogoutHandler processing request");

        if (!session.getClientSessions().contains(sessionCookieIds.getClientSessionId())) {
            LOG.warn("Client Session ID does not exist");
            return logoutService.generateErrorLogoutResponse(
                    Optional.empty(),
                    new ErrorObject(OAuth2Error.INVALID_REQUEST_CODE, "invalid session"),
                    input,
                    Optional.empty(),
                    Optional.of(session.getSessionId()));
        }

        Map<String, String> queryStringParameters = input.getQueryStringParameters();
        if (queryStringParameters == null || queryStringParameters.isEmpty()) {
            LOG.info("Deleting session and returning default logout as no input parameters");
            segmentedFunctionCall("destroySessions", () -> logoutService.destroySessions(session));
            return logoutService.generateDefaultLogoutResponse(
                    state, input, Optional.empty(), Optional.of(session.getSessionId()));
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
                return logoutService.generateErrorLogoutResponse(
                        Optional.empty(),
                        new ErrorObject(
                                OAuth2Error.INVALID_REQUEST_CODE,
                                "unable to validate id_token_hint"),
                        input,
                        Optional.empty(),
                        Optional.of(session.getSessionId()));
            }
            boolean isTokenSignatureValid =
                    segmentedFunctionCall(
                            "isTokenSignatureValid",
                            () -> tokenValidationService.isTokenSignatureValid(idTokenHint.get()));
            if (!isTokenSignatureValid) {
                LOG.warn("Unable to validate ID token signature");
                return logoutService.generateErrorLogoutResponse(
                        Optional.empty(),
                        new ErrorObject(
                                OAuth2Error.INVALID_REQUEST_CODE,
                                "unable to validate id_token_hint"),
                        input,
                        Optional.empty(),
                        Optional.of(session.getSessionId()));
            }

            try {
                SignedJWT idToken = SignedJWT.parse(idTokenHint.get());
                audience = idToken.getJWTClaimsSet().getAudience().stream().findFirst();
            } catch (ParseException e) {
                LOG.warn("Unable to parse id_token_hint into SignedJWT");
                return logoutService.generateErrorLogoutResponse(
                        Optional.empty(),
                        new ErrorObject(OAuth2Error.INVALID_REQUEST_CODE, "invalid id_token_hint"),
                        input,
                        Optional.empty(),
                        Optional.of(session.getSessionId()));
            }
        }
        segmentedFunctionCall("destroySessions", () -> logoutService.destroySessions(session));
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
            return logoutService.generateDefaultLogoutResponse(
                    state, input, audience, Optional.of(session.getSessionId()));
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
        attachLogFieldToLogs(CLIENT_ID, clientID);
        Optional<ClientRegistry> clientRegistry = dynamoClientService.getClient(clientID);
        if (clientRegistry.isEmpty()) {
            LOG.warn("Client not found in ClientRegistry");
            return logoutService.generateErrorLogoutResponse(
                    state,
                    new ErrorObject(OAuth2Error.UNAUTHORIZED_CLIENT_CODE, "client not found"),
                    input,
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
                                return logoutService.generateErrorLogoutResponse(
                                        state,
                                        new ErrorObject(
                                                OAuth2Error.INVALID_REQUEST_CODE,
                                                "client registry does not contain post_logout_redirect_uri"),
                                        input,
                                        Optional.of(clientID),
                                        sessionId);
                            } else {
                                LOG.info(
                                        "The post_logout_redirect_uri is present in logout request and client registry. Value is {}",
                                        uri);
                                cloudwatchMetricsService.incrementLogout(Optional.of(clientID));
                                return logoutService.generateLogoutResponse(
                                        URI.create(uri),
                                        state,
                                        Optional.empty(),
                                        input,
                                        Optional.of(clientID),
                                        sessionId);
                            }
                        })
                .orElseGet(
                        () -> {
                            LOG.info(
                                    "post_logout_redirect_uri is NOT present in logout request. Generating default logout response");
                            return logoutService.generateDefaultLogoutResponse(
                                    state, input, Optional.of(clientID), sessionId);
                        });
    }

    private boolean doesIDTokenExistInSession(String idTokenHint, Session session) {
        return session.getClientSessions().stream()
                .map(clientSessionService::getClientSession)
                .flatMap(Optional::stream)
                .anyMatch(cs -> idTokenHint.equals(cs.getIdTokenHint()));
    }
}

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
import uk.gov.di.orchestration.audit.TxmaAuditUser;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.Session;
import uk.gov.di.orchestration.shared.helpers.CookieHelper;
import uk.gov.di.orchestration.shared.services.CloudwatchMetricsService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.DynamoClientService;
import uk.gov.di.orchestration.shared.services.JwksService;
import uk.gov.di.orchestration.shared.services.KmsConnectionService;
import uk.gov.di.orchestration.shared.services.LogoutService;
import uk.gov.di.orchestration.shared.services.SessionService;
import uk.gov.di.orchestration.shared.services.TokenValidationService;

import java.net.URI;
import java.text.ParseException;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import static uk.gov.di.orchestration.shared.helpers.AuditHelper.attachTxmaAuditFieldFromHeaders;
import static uk.gov.di.orchestration.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.orchestration.shared.helpers.IpAddressHelper.extractIpAddress;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.CLIENT_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.CLIENT_SESSION_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.GOVUK_SIGNIN_JOURNEY_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachSessionIdToLogs;
import static uk.gov.di.orchestration.shared.helpers.PersistentIdHelper.extractPersistentIdFromCookieHeader;

public class LogoutHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(LogoutHandler.class);

    private final SessionService sessionService;
    private final DynamoClientService dynamoClientService;
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
            TokenValidationService tokenValidationService,
            CloudwatchMetricsService cloudwatchMetricsService,
            LogoutService logoutService) {
        this.sessionService = sessionService;
        this.dynamoClientService = dynamoClientService;
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
                "oidc-api::" + getClass().getSimpleName(), () -> logoutRequestHandler(input));
    }

    public APIGatewayProxyResponseEvent logoutRequestHandler(APIGatewayProxyRequestEvent input) {
        LOG.info("Logout request received");
        attachTxmaAuditFieldFromHeaders(input.getHeaders());
        Optional<Session> sessionFromSessionCookie =
                segmentedFunctionCall(
                        "getSessionFromSessionCookie",
                        () -> sessionService.getSessionFromSessionCookie(input.getHeaders()));
        attachSessionToLogsIfExists(sessionFromSessionCookie, input.getHeaders());

        var subjectId = sessionFromSessionCookie.map(Session::getInternalCommonSubjectIdentifier);
        var sessionId = sessionFromSessionCookie.map(Session::getSessionId);
        var journeyId = extractClientSessionIdFromCookieHeaders(input.getHeaders());

        var auditUser =
                TxmaAuditUser.user()
                        .withIpAddress(extractIpAddress(input))
                        .withPersistentSessionId(
                                extractPersistentIdFromCookieHeader(input.getHeaders()))
                        .withSessionId(sessionId.orElse(null))
                        .withGovukSigninJourneyId(journeyId.orElse(null))
                        .withUserId(subjectId.orElse(null));

        Map<String, String> queryStringParameters = input.getQueryStringParameters();
        if (queryStringParameters == null || queryStringParameters.isEmpty()) {
            LOG.info("Returning default logout as no input parameters");
            getSessionAndDestroyIfExists(sessionFromSessionCookie);
            return logoutService.generateDefaultLogoutResponse(
                    Optional.empty(), auditUser, Optional.empty());
        }
        Optional<String> state = Optional.ofNullable(queryStringParameters.get("state"));

        Optional<String> idTokenHint =
                Optional.ofNullable(queryStringParameters.get("id_token_hint"));
        if (idTokenHint.isEmpty()) {
            getSessionAndDestroyIfExists(sessionFromSessionCookie);
            return logoutService.generateDefaultLogoutResponse(state, auditUser, Optional.empty());
        }

        LOG.info("ID token hint is present");
        boolean isTokenSignatureValid =
                segmentedFunctionCall(
                        "isTokenSignatureValid",
                        () -> tokenValidationService.isTokenSignatureValid(idTokenHint.get()));
        if (!isTokenSignatureValid) {
            LOG.warn("Unable to validate ID token signature");
            return logoutService.generateErrorLogoutResponse(
                    Optional.empty(),
                    new ErrorObject(
                            OAuth2Error.INVALID_REQUEST_CODE, "unable to validate id_token_hint"),
                    auditUser,
                    Optional.empty());
        }

        Optional<String> audience;
        String rpPairwiseId;
        try {
            SignedJWT idToken = SignedJWT.parse(idTokenHint.get());
            audience = idToken.getJWTClaimsSet().getAudience().stream().findFirst();
            rpPairwiseId = idToken.getJWTClaimsSet().getSubject();
            var clientSessionId = idToken.getJWTClaimsSet().getStringClaim("sid");
            auditUser =
                    Objects.nonNull(clientSessionId)
                            ? auditUser.withGovukSigninJourneyId(clientSessionId)
                            : auditUser;
        } catch (ParseException e) {
            LOG.warn("Unable to extract JWTClaimsSet to get the audience");
            return logoutService.generateErrorLogoutResponse(
                    Optional.empty(),
                    new ErrorObject(OAuth2Error.INVALID_REQUEST_CODE, "invalid id_token_hint"),
                    auditUser,
                    Optional.empty());
        }

        if (audience.isEmpty() || rpPairwiseId == null) {
            getSessionAndDestroyIfExists(sessionFromSessionCookie);
            return logoutService.generateDefaultLogoutResponse(
                    Optional.empty(), auditUser, Optional.empty());
        }
        final String clientID = audience.get();

        LOG.info("Validating ClientID");
        attachLogFieldToLogs(CLIENT_ID, clientID);
        Optional<ClientRegistry> clientRegistry = dynamoClientService.getClient(clientID);
        if (clientRegistry.isEmpty()) {
            LOG.warn("Client not found in ClientRegistry");
            getSessionAndDestroyIfExists(sessionFromSessionCookie);
            return logoutService.generateErrorLogoutResponse(
                    state,
                    new ErrorObject(OAuth2Error.UNAUTHORIZED_CLIENT_CODE, "client not found"),
                    auditUser,
                    Optional.of(clientID));
        }

        Optional<String> postLogoutRedirectUri =
                Optional.ofNullable(queryStringParameters.get("post_logout_redirect_uri"));
        if (postLogoutRedirectUri.isEmpty()) {
            LOG.info(
                    "post_logout_redirect_uri is NOT present in logout request. Generating default logout response");
            getSessionAndDestroyIfExists(sessionFromSessionCookie);
            return logoutService.generateDefaultLogoutResponse(
                    state, auditUser, Optional.of(clientID), Optional.of(rpPairwiseId));
        }

        if (!postLogoutRedirectUriInClientReg(postLogoutRedirectUri, clientRegistry)) {
            getSessionAndDestroyIfExists(sessionFromSessionCookie);
            return logoutService.generateErrorLogoutResponse(
                    state,
                    new ErrorObject(
                            OAuth2Error.INVALID_REQUEST_CODE,
                            "client registry does not contain post_logout_redirect_uri"),
                    auditUser,
                    Optional.of(clientID));
        }

        var finalAuditUser = auditUser;
        if (sessionFromSessionCookie.isPresent()) {
            return segmentedFunctionCall(
                    "logoutWhenSessionExists",
                    () ->
                            logout(
                                    sessionFromSessionCookie.get(),
                                    clientID,
                                    postLogoutRedirectUri.get(),
                                    state,
                                    finalAuditUser,
                                    rpPairwiseId));

        } else {
            return segmentedFunctionCall(
                    "logoutWhenSessionDoesNotExist",
                    () ->
                            logoutService.generateLogoutResponse(
                                    URI.create(postLogoutRedirectUri.get()),
                                    state,
                                    Optional.empty(),
                                    finalAuditUser,
                                    Optional.of(clientID),
                                    Optional.of(rpPairwiseId)));
        }
    }

    private void attachSessionToLogsIfExists(
            Optional<Session> sessionFromSessionCookie, Map<String, String> headers) {
        if (sessionFromSessionCookie.isPresent()) {
            Session session = sessionFromSessionCookie.get();
            var clientSessionId = extractClientSessionIdFromCookieHeaders(headers);

            attachSessionIdToLogs(session);
            attachLogFieldToLogs(CLIENT_SESSION_ID, clientSessionId.orElse(null));
            attachLogFieldToLogs(GOVUK_SIGNIN_JOURNEY_ID, clientSessionId.orElse(null));
        }
    }

    private Optional<String> extractClientSessionIdFromCookieHeaders(Map<String, String> headers) {
        var sessionCookieIds = cookieHelper.parseSessionCookie(headers);
        return sessionCookieIds.map(CookieHelper.SessionCookieIds::getClientSessionId);
    }

    private Optional<String> getSessionAndDestroyIfExists(
            Optional<Session> sessionFromSessionCookie) {
        if (sessionFromSessionCookie.isPresent()) {
            Session session = sessionFromSessionCookie.get();
            segmentedFunctionCall("destroySessions", () -> logoutService.destroySessions(session));
            return Optional.of(session.getSessionId());
        } else {
            return Optional.empty();
        }
    }

    private boolean postLogoutRedirectUriInClientReg(
            Optional<String> postLogoutRedirectUri, Optional<ClientRegistry> clientRegistry) {
        return postLogoutRedirectUri
                .map(
                        uri -> {
                            if (!clientRegistry.get().getPostLogoutRedirectUrls().contains(uri)) {
                                LOG.warn(
                                        "Client registry does not contain PostLogoutRedirectUri which was sent in the logout request. Value is {}",
                                        uri);
                                return false;
                            } else {
                                LOG.info(
                                        "The post_logout_redirect_uri is present in logout request and client registry. Value is {}",
                                        uri);
                                return true;
                            }
                        })
                .orElseGet(() -> false);
    }

    private APIGatewayProxyResponseEvent logout(
            Session session,
            String clientID,
            String uri,
            Optional<String> state,
            TxmaAuditUser auditUser,
            String rpPairwiseId) {

        segmentedFunctionCall("destroySessions", () -> logoutService.destroySessions(session));
        cloudwatchMetricsService.incrementLogout(Optional.of(clientID));
        return logoutService.generateLogoutResponse(
                URI.create(uri),
                state,
                Optional.empty(),
                auditUser,
                Optional.of(clientID),
                Optional.of(rpPairwiseId));
    }
}

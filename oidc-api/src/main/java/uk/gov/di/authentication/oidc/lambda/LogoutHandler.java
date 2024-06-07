package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.authentication.oidc.entity.LogoutRequest;
import uk.gov.di.orchestration.shared.entity.Session;
import uk.gov.di.orchestration.shared.helpers.CookieHelper;
import uk.gov.di.orchestration.shared.services.CloudwatchMetricsService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.DynamoClientService;
import uk.gov.di.orchestration.shared.services.JwksService;
import uk.gov.di.orchestration.shared.services.KmsConnectionService;
import uk.gov.di.orchestration.shared.services.LogoutService;
import uk.gov.di.orchestration.shared.services.RedisConnectionService;
import uk.gov.di.orchestration.shared.services.SessionService;
import uk.gov.di.orchestration.shared.services.TokenValidationService;

import java.net.URI;
import java.util.Map;

import static uk.gov.di.orchestration.shared.helpers.AuditHelper.attachTxmaAuditFieldFromHeaders;
import static uk.gov.di.orchestration.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.CLIENT_SESSION_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.GOVUK_SIGNIN_JOURNEY_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachSessionIdToLogs;

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

    public LogoutHandler(ConfigurationService configurationService, RedisConnectionService redis) {
        this.sessionService = new SessionService(configurationService, redis);
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

        LogoutRequest logoutRequest =
                new LogoutRequest(
                        sessionService, tokenValidationService, dynamoClientService, input);

        if (logoutRequest.session().isPresent()) {
            Session session = logoutRequest.session().get();
            attachSessionToLogs(session, input.getHeaders());
            segmentedFunctionCall("destroySessions", () -> logoutService.destroySessions(session));
            cloudwatchMetricsService.incrementLogout(logoutRequest.clientId());
        }

        return logoutService.handleLogout(
                logoutRequest.errorObject(),
                logoutRequest.postLogoutRedirectUri().map(URI::create),
                logoutRequest.state(),
                logoutRequest.auditUser(),
                logoutRequest.clientId(),
                logoutRequest.rpPairwiseId());
    }

    private void attachSessionToLogs(Session session, Map<String, String> headers) {
        CookieHelper.SessionCookieIds sessionCookieIds =
                cookieHelper.parseSessionCookie(headers).orElseThrow();
        attachSessionIdToLogs(session);
        attachLogFieldToLogs(CLIENT_SESSION_ID, sessionCookieIds.getClientSessionId());
        attachLogFieldToLogs(GOVUK_SIGNIN_JOURNEY_ID, sessionCookieIds.getClientSessionId());
    }
}

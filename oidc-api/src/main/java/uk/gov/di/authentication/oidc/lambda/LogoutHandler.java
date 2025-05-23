package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.authentication.oidc.entity.LogoutRequest;
import uk.gov.di.orchestration.shared.helpers.CookieHelper;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.DynamoClientService;
import uk.gov.di.orchestration.shared.services.JwksService;
import uk.gov.di.orchestration.shared.services.KmsConnectionService;
import uk.gov.di.orchestration.shared.services.LogoutService;
import uk.gov.di.orchestration.shared.services.OrchSessionService;
import uk.gov.di.orchestration.shared.services.TokenValidationService;

import java.util.Map;

import static uk.gov.di.orchestration.shared.helpers.AuditHelper.attachTxmaAuditFieldFromHeaders;
import static uk.gov.di.orchestration.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.AWS_REQUEST_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.CLIENT_SESSION_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.GOVUK_SIGNIN_JOURNEY_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachSessionIdToLogs;

public class LogoutHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(LogoutHandler.class);

    private final DynamoClientService dynamoClientService;
    private final TokenValidationService tokenValidationService;
    private final OrchSessionService orchSessionService;

    private final LogoutService logoutService;

    public LogoutHandler() {
        this(ConfigurationService.getInstance());
    }

    public LogoutHandler(ConfigurationService configurationService) {
        this.dynamoClientService = new DynamoClientService(configurationService);
        this.tokenValidationService =
                new TokenValidationService(
                        new JwksService(
                                configurationService,
                                new KmsConnectionService(configurationService)),
                        configurationService);
        this.logoutService = new LogoutService(configurationService);
        this.orchSessionService = new OrchSessionService(configurationService);
    }

    public LogoutHandler(
            DynamoClientService dynamoClientService,
            TokenValidationService tokenValidationService,
            LogoutService logoutService,
            OrchSessionService orchSessionService) {
        this.dynamoClientService = dynamoClientService;
        this.tokenValidationService = tokenValidationService;
        this.logoutService = logoutService;
        this.orchSessionService = orchSessionService;
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        ThreadContext.clearMap();
        attachLogFieldToLogs(AWS_REQUEST_ID, context.getAwsRequestId());
        return segmentedFunctionCall(
                "oidc-api::" + getClass().getSimpleName(), () -> logoutRequestHandler(input));
    }

    public APIGatewayProxyResponseEvent logoutRequestHandler(APIGatewayProxyRequestEvent input) {
        LOG.info("Logout request received");
        attachTxmaAuditFieldFromHeaders(input.getHeaders());

        LogoutRequest logoutRequest =
                new LogoutRequest(
                        tokenValidationService, dynamoClientService, input, orchSessionService);

        logoutRequest
                .sessionId()
                .ifPresent(sessionId -> attachSessionToLogs(sessionId, input.getHeaders()));
        return logoutService.handleLogout(
                logoutRequest.destroySessionsRequest(),
                logoutRequest.errorObject(),
                logoutRequest.postLogoutRedirectUri(),
                logoutRequest.state(),
                logoutRequest.auditUser(),
                logoutRequest.clientId(),
                logoutRequest.rpPairwiseId());
    }

    private void attachSessionToLogs(String sessionId, Map<String, String> headers) {
        CookieHelper.SessionCookieIds sessionCookieIds =
                CookieHelper.parseSessionCookie(headers).orElseThrow();
        attachSessionIdToLogs(sessionId);
        attachLogFieldToLogs(CLIENT_SESSION_ID, sessionCookieIds.getClientSessionId());
        attachLogFieldToLogs(GOVUK_SIGNIN_JOURNEY_ID, sessionCookieIds.getClientSessionId());
    }
}

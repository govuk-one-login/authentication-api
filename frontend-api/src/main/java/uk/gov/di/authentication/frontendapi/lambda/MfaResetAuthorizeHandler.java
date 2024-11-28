package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.frontendapi.entity.MfaResetRequest;
import uk.gov.di.authentication.frontendapi.entity.MfaResetResponse;
import uk.gov.di.authentication.frontendapi.services.IPVReverificationService;
import uk.gov.di.authentication.frontendapi.services.JwtService;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.lambda.BaseFrontendHandler;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.services.TokenService;
import uk.gov.di.authentication.shared.state.UserContext;

import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_REVERIFY_AUTHORISATION_REQUESTED;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1060;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.CLIENT_SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachLogFieldToLogs;

public class MfaResetAuthorizeHandler extends BaseFrontendHandler<MfaResetRequest>
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private static final Logger LOG = LogManager.getLogger(MfaResetAuthorizeHandler.class);
    private final IPVReverificationService ipvReverificationService;
    private final AuditService auditService;
    private final CloudwatchMetricsService cloudwatchMetricsService;

    public MfaResetAuthorizeHandler(
            ConfigurationService configurationService,
            SessionService sessionService,
            AuthSessionService authSessionService,
            ClientSessionService clientSessionService,
            ClientService clientService,
            AuthenticationService authenticationService,
            IPVReverificationService ipvReverificationService,
            AuditService auditService,
            CloudwatchMetricsService cloudwatchMetricsService) {
        super(
                MfaResetRequest.class,
                configurationService,
                sessionService,
                authSessionService,
                clientSessionService,
                clientService,
                authenticationService);
        this.ipvReverificationService = ipvReverificationService;
        this.auditService = auditService;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
    }

    public MfaResetAuthorizeHandler(ConfigurationService configurationService) {
        super(MfaResetRequest.class, configurationService);
        RedisConnectionService redisConnectionService =
                new RedisConnectionService(configurationService);
        KmsConnectionService kmsConnectionService = new KmsConnectionService(configurationService);
        JwtService jwtService = new JwtService(kmsConnectionService);
        TokenService tokenService =
                new TokenService(
                        configurationService, redisConnectionService, kmsConnectionService);
        this.auditService = new AuditService(configurationService);
        this.cloudwatchMetricsService = new CloudwatchMetricsService(configurationService);
        this.ipvReverificationService =
                new IPVReverificationService(
                        configurationService, jwtService, tokenService, redisConnectionService);
    }

    public MfaResetAuthorizeHandler() {
        this(ConfigurationService.getInstance());
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return super.handleRequest(input, context);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequestWithUserContext(
            APIGatewayProxyRequestEvent input,
            Context context,
            MfaResetRequest request,
            UserContext userContext) {
        LOG.info("MFA Reset Authorization request received");
        try {
            Session userSession = userContext.getSession();
            String clientSessionId = userContext.getClientSessionId();
            attachLogFieldToLogs(CLIENT_SESSION_ID, clientSessionId);

            AuditContext auditContext =
                    AuditContext.auditContextFromUserContext(
                            userContext,
                            AuditService.UNKNOWN,
                            request.email(),
                            IpAddressHelper.extractIpAddress(input),
                            AuditService.UNKNOWN,
                            PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders()));

            Subject internalCommonSubjectId =
                    new Subject(userSession.getInternalCommonSubjectIdentifier());

            var ipvReverificationRequestURI =
                    ipvReverificationService.buildIpvReverificationRedirectUri(
                            internalCommonSubjectId, clientSessionId, userSession);

            auditService.submitAuditEvent(AUTH_REVERIFY_AUTHORISATION_REQUESTED, auditContext);
            cloudwatchMetricsService.incrementMfaResetHandoffCount();

            return generateApiGatewayProxyResponse(
                    200, new MfaResetResponse(ipvReverificationRequestURI));
        } catch (Json.JsonException | RuntimeException e) {
            LOG.error("Error building the IPV reverification request.", e);
            return generateApiGatewayProxyResponse(500, ERROR_1060.getMessage());
        }
    }
}

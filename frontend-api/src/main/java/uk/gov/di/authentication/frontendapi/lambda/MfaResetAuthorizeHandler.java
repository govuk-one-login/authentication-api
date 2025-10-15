package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.frontendapi.entity.MfaResetRequest;
import uk.gov.di.authentication.frontendapi.entity.MfaResetResponse;
import uk.gov.di.authentication.frontendapi.services.IPVReverificationService;
import uk.gov.di.authentication.frontendapi.services.JwtService;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.lambda.BaseFrontendHandler;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.IDReverificationStateService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.TokenService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.net.MalformedURLException;

import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_REVERIFY_AUTHORISATION_REQUESTED;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_JOURNEY_TYPE;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.MFA_RESET_JAR_GENERATION_ERROR;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.CLIENT_SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;

public class MfaResetAuthorizeHandler extends BaseFrontendHandler<MfaResetRequest>
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private static final Logger LOG = LogManager.getLogger(MfaResetAuthorizeHandler.class);
    private final IPVReverificationService ipvReverificationService;
    private final AuditService auditService;
    private final CloudwatchMetricsService cloudwatchMetricsService;
    private final IDReverificationStateService idReverificationStateService;

    public MfaResetAuthorizeHandler(
            ConfigurationService configurationService,
            AuthenticationService authenticationService,
            IPVReverificationService ipvReverificationService,
            AuditService auditService,
            CloudwatchMetricsService cloudwatchMetricsService,
            IDReverificationStateService idReverificationStateService,
            AuthSessionService authSessionService) {
        super(
                MfaResetRequest.class,
                configurationService,
                authenticationService,
                authSessionService);
        this.ipvReverificationService = ipvReverificationService;
        this.auditService = auditService;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
        this.idReverificationStateService = idReverificationStateService;
    }

    public MfaResetAuthorizeHandler(ConfigurationService configurationService) {
        super(MfaResetRequest.class, configurationService);
        this.auditService = new AuditService(configurationService);
        this.cloudwatchMetricsService = new CloudwatchMetricsService(configurationService);
        this.idReverificationStateService = new IDReverificationStateService(configurationService);
        this.ipvReverificationService = new IPVReverificationService(configurationService);
    }

    public MfaResetAuthorizeHandler(RedisConnectionService redisConnectionService)
            throws MalformedURLException {
        super(MfaResetRequest.class, ConfigurationService.getInstance());
        KmsConnectionService kmsConnectionService = new KmsConnectionService(configurationService);
        JwtService jwtService = new JwtService(kmsConnectionService);
        TokenService tokenService =
                new TokenService(
                        configurationService, redisConnectionService, kmsConnectionService);
        this.auditService = new AuditService(configurationService);
        this.cloudwatchMetricsService = new CloudwatchMetricsService(configurationService);
        this.ipvReverificationService =
                new IPVReverificationService(configurationService, jwtService, tokenService);
        this.idReverificationStateService = new IDReverificationStateService(configurationService);
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
            String clientSessionId = userContext.getClientSessionId();
            AuthSessionItem authSession = userContext.getAuthSession();
            attachLogFieldToLogs(CLIENT_SESSION_ID, clientSessionId);

            AuditContext auditContext =
                    AuditContext.auditContextFromUserContext(
                            userContext,
                            userContext.getAuthSession().getInternalCommonSubjectId(),
                            request.email(),
                            IpAddressHelper.extractIpAddress(input),
                            AuditService.UNKNOWN,
                            PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders()));

            Subject internalCommonSubjectId = new Subject(authSession.getInternalCommonSubjectId());

            State authenticationState = new State();
            var ipvReverificationRequestURI =
                    ipvReverificationService.buildIpvReverificationRedirectUri(
                            internalCommonSubjectId, clientSessionId, authenticationState);

            idReverificationStateService.store(
                    authenticationState.getValue(),
                    request.orchestrationRedirectUrl(),
                    userContext.getClientSessionId());

            var userProfile =
                    userContext
                            .getUserProfile()
                            .orElseThrow(() -> new RuntimeException("UserProfile not found"));

            String rpPairwiseId =
                    ClientSubjectHelper.getSubject(userProfile, authSession, authenticationService)
                            .toString();

            authSessionService.updateSession(
                    userContext
                            .getAuthSession()
                            .withResetMfaState(AuthSessionItem.ResetMfaState.ATTEMPTED));

            auditService.submitAuditEvent(
                    AUTH_REVERIFY_AUTHORISATION_REQUESTED,
                    auditContext,
                    pair("rpPairwiseId", rpPairwiseId),
                    pair(
                            AUDIT_EVENT_EXTENSIONS_JOURNEY_TYPE,
                            JourneyType.ACCOUNT_RECOVERY.getValue()));
            cloudwatchMetricsService.incrementMfaResetHandoffCount();

            return generateApiGatewayProxyResponse(
                    200, new MfaResetResponse(ipvReverificationRequestURI));
        } catch (Json.JsonException | RuntimeException e) {
            LOG.error("Error building the IPV reverification request.", e);
            return generateApiGatewayProxyResponse(
                    500, MFA_RESET_JAR_GENERATION_ERROR.getMessage());
        }
    }
}

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
import uk.gov.di.authentication.frontendapi.exceptions.JwtServiceException;
import uk.gov.di.authentication.frontendapi.services.JwtService;
import uk.gov.di.authentication.frontendapi.services.MfaResetIPVAuthorizationService;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.lambda.BaseFrontendHandler;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuditService;
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

import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1060;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.CLIENT_SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachLogFieldToLogs;

public class MfaResetAuthorizeHandler extends BaseFrontendHandler<MfaResetRequest>
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private static final Logger LOG = LogManager.getLogger(MfaResetAuthorizeHandler.class);
    private final MfaResetIPVAuthorizationService mfaResetIPVAuthorizationService;

    public MfaResetAuthorizeHandler(
            ConfigurationService configurationService,
            SessionService sessionService,
            ClientSessionService clientSessionService,
            ClientService clientService,
            AuthenticationService authenticationService,
            MfaResetIPVAuthorizationService mfaResetIPVAuthorizationService) {
        super(
                MfaResetRequest.class,
                configurationService,
                sessionService,
                clientSessionService,
                clientService,
                authenticationService);
        this.mfaResetIPVAuthorizationService = mfaResetIPVAuthorizationService;
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
        this.mfaResetIPVAuthorizationService =
                new MfaResetIPVAuthorizationService(
                        configurationService,
                        jwtService,
                        tokenService,
                        redisConnectionService,
                        new AuditService(configurationService),
                        new CloudwatchMetricsService(configurationService));
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

            return mfaResetIPVAuthorizationService.buildMfaResetIpvRedirectRequest(
                    internalCommonSubjectId, clientSessionId, userSession, auditContext);
        } catch (JwtServiceException e) {
            LOG.error("Error in JWT service", e);
            return generateApiGatewayProxyResponse(500, ERROR_1060.getMessage());
        } catch (Json.JsonException e) {
            LOG.error("Error serialising MFA reset response", e);
            throw new RuntimeException(e);
        }
    }
}

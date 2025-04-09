package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.frontendapi.entity.UpdateProfileRequest;
import uk.gov.di.authentication.shared.domain.AuditableEvent;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.LogLineHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.lambda.BaseFrontendHandler;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.Optional;

import static uk.gov.di.audit.AuditContext.auditContextFromUserContext;
import static uk.gov.di.audit.AuditContext.emptyAuditContext;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_UPDATE_PROFILE_REQUEST_ERROR;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_UPDATE_PROFILE_REQUEST_RECEIVED;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_UPDATE_PROFILE_TERMS_CONDS_ACCEPTANCE;
import static uk.gov.di.authentication.frontendapi.entity.UpdateProfileType.UPDATE_TERMS_CONDS;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateEmptySuccessApiGatewayResponse;

public class UpdateProfileHandler extends BaseFrontendHandler<UpdateProfileRequest>
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(UpdateProfileHandler.class);

    private final AuditService auditService;

    protected UpdateProfileHandler(
            AuthenticationService authenticationService,
            SessionService sessionService,
            ClientSessionService clientSessionService,
            ConfigurationService configurationService,
            AuditService auditService,
            ClientService clientService,
            AuthSessionService authSessionService) {
        super(
                UpdateProfileRequest.class,
                configurationService,
                sessionService,
                clientSessionService,
                clientService,
                authenticationService,
                authSessionService);
        this.auditService = auditService;
    }

    public UpdateProfileHandler() {
        this(ConfigurationService.getInstance());
    }

    public UpdateProfileHandler(ConfigurationService configurationService) {
        super(UpdateProfileRequest.class, configurationService);
        auditService = new AuditService(configurationService);
    }

    public UpdateProfileHandler(
            ConfigurationService configurationService, RedisConnectionService redis) {
        super(UpdateProfileRequest.class, configurationService, redis);
        auditService = new AuditService(configurationService);
    }

    @Override
    public void onRequestReceived(String clientSessionId, String txmaAuditEncoded) {
        auditService.submitAuditEvent(
                AUTH_UPDATE_PROFILE_REQUEST_RECEIVED,
                auditContextWithOnlyClientSessionId(clientSessionId, txmaAuditEncoded));
    }

    @Override
    public void onRequestValidationError(String clientSessionId, String txmaAuditEncoded) {
        auditService.submitAuditEvent(
                AUTH_UPDATE_PROFILE_REQUEST_ERROR,
                auditContextWithOnlyClientSessionId(clientSessionId, txmaAuditEncoded));
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
            UpdateProfileRequest request,
            UserContext userContext) {

        Session session = userContext.getSession();
        AuthSessionItem authSession = userContext.getAuthSession();

        String persistentSessionId =
                PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders());

        LogLineHelper.attachSessionIdToLogs(userContext.getAuthSession().getSessionId());

        LOG.info("Processing request");

        String ipAddress = IpAddressHelper.extractIpAddress(input);

        if (!authSession.validateSession(request.getEmail())) {
            LOG.info("Invalid session");
            return generateErrorResponse(
                    ErrorResponse.ERROR_1000,
                    auditContextWithOnlyClientSessionId(
                            userContext.getClientSessionId(), userContext.getTxmaAuditEncoded()));
        }

        AuditableEvent auditableEvent;
        String auditablePhoneNumber =
                userContext
                        .getUserProfile()
                        .map(UserProfile::getPhoneNumber)
                        .orElse(AuditService.UNKNOWN);
        var auditContext =
                auditContextFromUserContext(
                        userContext,
                        authSession.getInternalCommonSubjectId(),
                        authSession.getEmailAddress(),
                        ipAddress,
                        auditablePhoneNumber,
                        persistentSessionId);

        if (request.getUpdateProfileType().equals(UPDATE_TERMS_CONDS)) {
            authenticationService.updateTermsAndConditions(
                    request.getEmail(), configurationService.getTermsAndConditionsVersion());
            auditableEvent = AUTH_UPDATE_PROFILE_TERMS_CONDS_ACCEPTANCE;
            LOG.info(
                    "Updated terms and conditions for Version: {}",
                    configurationService.getTermsAndConditionsVersion());
        } else {
            LOG.error(
                    "Encountered unexpected error while processing session: {}",
                    userContext.getAuthSession().getSessionId());
            return generateErrorResponse(ErrorResponse.ERROR_1013, auditContext);
        }

        auditService.submitAuditEvent(auditableEvent, auditContext);
        return generateEmptySuccessApiGatewayResponse();
    }

    private APIGatewayProxyResponseEvent generateErrorResponse(
            ErrorResponse errorResponse, AuditContext auditContext) {
        auditService.submitAuditEvent(AUTH_UPDATE_PROFILE_REQUEST_ERROR, auditContext);
        return generateApiGatewayProxyErrorResponse(400, errorResponse);
    }

    private AuditContext auditContextWithOnlyClientSessionId(
            String clientSessionId, String txmaAuditEncoded) {
        return emptyAuditContext()
                .withClientSessionId(clientSessionId)
                .withTxmaAuditEncoded(Optional.ofNullable(txmaAuditEncoded));
    }
}

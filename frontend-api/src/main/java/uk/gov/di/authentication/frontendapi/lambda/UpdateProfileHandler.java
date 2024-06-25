package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.frontendapi.entity.UpdateProfileRequest;
import uk.gov.di.authentication.shared.domain.AuditableEvent;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.LogLineHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.lambda.BaseFrontendHandler;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.Optional;

import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.UPDATE_PROFILE_REQUEST_ERROR;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.UPDATE_PROFILE_REQUEST_RECEIVED;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.UPDATE_PROFILE_TERMS_CONDS_ACCEPTANCE;
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
            ClientService clientService) {
        super(
                UpdateProfileRequest.class,
                configurationService,
                sessionService,
                clientSessionService,
                clientService,
                authenticationService);
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
        var restrictedSection =
                new AuditService.RestrictedSection(Optional.ofNullable(txmaAuditEncoded));

        auditService.submitAuditEvent(
                UPDATE_PROFILE_REQUEST_RECEIVED,
                AuditService.UNKNOWN,
                clientSessionId,
                AuditService.UNKNOWN,
                AuditService.UNKNOWN,
                AuditService.UNKNOWN,
                AuditService.UNKNOWN,
                AuditService.UNKNOWN,
                AuditService.UNKNOWN,
                restrictedSection);
    }

    @Override
    public void onRequestValidationError(String clientSessionId, String txmaAuditEncoded) {
        var restrictedSection =
                new AuditService.RestrictedSection(Optional.ofNullable(txmaAuditEncoded));

        auditService.submitAuditEvent(
                UPDATE_PROFILE_REQUEST_ERROR,
                AuditService.UNKNOWN,
                clientSessionId,
                AuditService.UNKNOWN,
                AuditService.UNKNOWN,
                AuditService.UNKNOWN,
                AuditService.UNKNOWN,
                AuditService.UNKNOWN,
                AuditService.UNKNOWN,
                restrictedSection);
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

        String persistentSessionId =
                PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders());

        LogLineHelper.attachSessionIdToLogs(session);

        LOG.info("Processing request");

        String ipAddress = IpAddressHelper.extractIpAddress(input);

        if (!session.validateSession(request.getEmail())) {
            LOG.info("Invalid session");
            return generateErrorResponse(
                    ErrorResponse.ERROR_1000,
                    userContext.getClientSessionId(),
                    AuditService.UNKNOWN,
                    AuditService.UNKNOWN,
                    AuditService.UNKNOWN,
                    persistentSessionId,
                    AuditService.UNKNOWN,
                    userContext.getTxmaAuditEncoded());
        }

        AuditableEvent auditableEvent;
        String auditablePhoneNumber =
                userContext
                        .getUserProfile()
                        .map(UserProfile::getPhoneNumber)
                        .orElse(AuditService.UNKNOWN);
        String auditableClientId =
                userContext
                        .getClient()
                        .map(ClientRegistry::getClientID)
                        .orElse(AuditService.UNKNOWN);
        if (request.getUpdateProfileType().equals(UPDATE_TERMS_CONDS)) {
            authenticationService.updateTermsAndConditions(
                    request.getEmail(), configurationService.getTermsAndConditionsVersion());
            auditableEvent = UPDATE_PROFILE_TERMS_CONDS_ACCEPTANCE;
            LOG.info(
                    "Updated terms and conditions for Version: {}",
                    configurationService.getTermsAndConditionsVersion());
        } else {
            LOG.error(
                    "Encountered unexpected error while processing session: {}",
                    session.getSessionId());
            return generateErrorResponse(
                    ErrorResponse.ERROR_1013,
                    userContext.getClientSessionId(),
                    session.getSessionId(),
                    auditableClientId,
                    request.getEmail(),
                    persistentSessionId,
                    session.getInternalCommonSubjectIdentifier(),
                    AuditService.UNKNOWN);
        }
        var restrictedSection =
                new AuditService.RestrictedSection(
                        Optional.ofNullable(userContext.getTxmaAuditEncoded()));

        auditService.submitAuditEvent(
                auditableEvent,
                auditableClientId,
                userContext.getClientSessionId(),
                session.getSessionId(),
                session.getInternalCommonSubjectIdentifier(),
                session.getEmailAddress(),
                ipAddress,
                auditablePhoneNumber,
                persistentSessionId,
                restrictedSection);
        return generateEmptySuccessApiGatewayResponse();
    }

    private APIGatewayProxyResponseEvent generateErrorResponse(
            ErrorResponse errorResponse,
            String clientSessionId,
            String sessionId,
            String clientId,
            String email,
            String persistentSessionId,
            String subjectId,
            String txmaAuditEncoded) {
        var restrictedSection =
                new AuditService.RestrictedSection(Optional.ofNullable(txmaAuditEncoded));

        auditService.submitAuditEvent(
                UPDATE_PROFILE_REQUEST_ERROR,
                clientId,
                clientSessionId,
                sessionId,
                subjectId,
                email,
                AuditService.UNKNOWN,
                AuditService.UNKNOWN,
                persistentSessionId,
                restrictedSection);
        return generateApiGatewayProxyErrorResponse(400, errorResponse);
    }
}

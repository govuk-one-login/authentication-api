package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jspecify.annotations.NonNull;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.frontendapi.entity.UpdateProfileRequest;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.LogLineHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.lambda.BaseFrontendHandler;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.state.UserContext;

import static uk.gov.di.audit.AuditContext.auditContextFromUserContext;
import static uk.gov.di.audit.AuditContext.emptyAuditContext;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_UPDATE_PROFILE_REQUEST_ERROR;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_UPDATE_PROFILE_REQUEST_RECEIVED;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_UPDATE_PROFILE_TERMS_CONDS_ACCEPTANCE;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateEmptySuccessApiGatewayResponse;

public class UpdateProfileHandler extends BaseFrontendHandler<UpdateProfileRequest>
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(UpdateProfileHandler.class);

    private final AuditService auditService;

    protected UpdateProfileHandler(
            AuthenticationService authenticationService,
            ConfigurationService configurationService,
            AuditService auditService,
            AuthSessionService authSessionService) {
        super(
                UpdateProfileRequest.class,
                configurationService,
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

        AuthSessionItem authSession = userContext.getAuthSession();
        LogLineHelper.attachSessionIdToLogs(userContext.getAuthSession().getSessionId());
        LOG.info("Processing request");

        if (!authSession.validateSession(request.getEmail())) {
            LOG.info("Invalid session");
            return generateErrorResponse(
                    ErrorResponse.SESSION_ID_MISSING,
                    auditContextWithOnlyClientSessionId(
                            userContext.getClientSessionId(), userContext.getTxmaAuditEncoded()));
        }

        var auditContext = buildAuditContext(input, userContext, authSession);

        switch (request.getUpdateProfileType()) {
            case UPDATE_TERMS_CONDS -> {
                authenticationService.updateTermsAndConditions(
                        request.getEmail(), configurationService.getTermsAndConditionsVersion());
                LOG.info(
                        "Updated terms and conditions for Version: {}",
                        configurationService.getTermsAndConditionsVersion());
                auditService.submitAuditEvent(
                        AUTH_UPDATE_PROFILE_TERMS_CONDS_ACCEPTANCE, auditContext);
            }
            default -> {
                LOG.error(
                        "Encountered unexpected error while processing session: {}",
                        userContext.getAuthSession().getSessionId());
                return generateErrorResponse(
                        ErrorResponse.INVALID_UPDATE_PROFILE_TYPE, auditContext);
            }
        }

        return generateEmptySuccessApiGatewayResponse();
    }

    private static @NonNull AuditContext buildAuditContext(
            APIGatewayProxyRequestEvent input,
            UserContext userContext,
            AuthSessionItem authSession) {
        String persistentSessionId =
                PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders());

        String ipAddress = IpAddressHelper.extractIpAddress(input);

        String auditablePhoneNumber =
                userContext
                        .getUserProfile()
                        .map(UserProfile::getPhoneNumber)
                        .orElse(AuditService.UNKNOWN);

        return auditContextFromUserContext(
                userContext,
                authSession.getInternalCommonSubjectId(),
                authSession.getEmailAddress(),
                ipAddress,
                auditablePhoneNumber,
                persistentSessionId);
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
                .withTxmaAuditEncoded(txmaAuditEncoded);
    }
}

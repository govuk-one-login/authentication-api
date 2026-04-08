package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.accountmanagement.entity.AuthenticateRequest;
import uk.gov.di.accountmanagement.helpers.AuditHelper;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.shared.entity.AccountInterventionsInboundResponse;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.exceptions.UnsuccessfulAccountInterventionsResponseException;
import uk.gov.di.authentication.shared.helpers.*;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.serialization.Json.JsonException;
import uk.gov.di.authentication.shared.services.*;

import java.util.ArrayList;
import java.util.Optional;

import static uk.gov.di.accountmanagement.constants.AccountManagementConstants.AUDIT_EVENT_COMPONENT_ID_AUTH;
import static uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent.*;
import static uk.gov.di.authentication.shared.domain.RequestHeaders.SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateEmptySuccessApiGatewayResponse;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachSessionIdToLogs;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachTraceId;

public class AuthenticateHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(AuthenticateHandler.class);

    private final AuthenticationService authenticationService;
    private final Json objectMapper = SerializationService.getInstance();
    private final AuditService auditService;
    private final ConfigurationService configurationService;
    private final AccountInterventionsService accountInterventionsService;

    public AuthenticateHandler(
            AuthenticationService authenticationService,
            AuditService auditService,
            ConfigurationService configurationService,
            AccountInterventionsService accountInterventionsService) {
        this.authenticationService = authenticationService;
        this.auditService = auditService;
        this.configurationService = configurationService;
        this.accountInterventionsService = accountInterventionsService;
    }

    public AuthenticateHandler() {
        this(ConfigurationService.getInstance());
    }

    public AuthenticateHandler(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.authenticationService = new DynamoService(configurationService);
        this.auditService = new AuditService(configurationService);
        this.accountInterventionsService = new AccountInterventionsService(configurationService);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        ThreadContext.clearMap();
        return segmentedFunctionCall(
                "account-management-api::" + getClass().getSimpleName(),
                () -> authenticateRequestHandler(input, context));
    }

    public APIGatewayProxyResponseEvent authenticateRequestHandler(
            APIGatewayProxyRequestEvent input, Context context) {
        String sessionId =
                RequestHeaderHelper.getHeaderValueOrElse(input.getHeaders(), SESSION_ID_HEADER, "");
        attachTraceId();
        attachSessionIdToLogs(sessionId);
        LOG.info("Request received to the AuthenticateHandler");

        var auditContext =
                new AuditContext(
                        AuditService.UNKNOWN,
                        ClientSessionIdHelper.extractSessionIdFromHeaders(input.getHeaders()),
                        sessionId,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        IpAddressHelper.extractIpAddress(input),
                        AuditService.UNKNOWN,
                        PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders()),
                        AuditHelper.getTxmaAuditEncoded(input.getHeaders()),
                        new ArrayList<>());

        try {
            AuthenticateRequest loginRequest =
                    objectMapper.readValue(input.getBody(), AuthenticateRequest.class);
            auditContext = auditContext.withEmail(loginRequest.getEmail());
            Optional<UserProfile> userProfile =
                    authenticationService.getUserProfileByEmailMaybe(loginRequest.getEmail());
            if (userProfile.isEmpty()) {
                auditService.submitAuditEvent(
                        AUTH_ACCOUNT_MANAGEMENT_AUTHENTICATE_FAILURE,
                        auditContext,
                        AUDIT_EVENT_COMPONENT_ID_AUTH);
                return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ACCT_DOES_NOT_EXIST);
            }
            var internalCommonSubjectIdentifier =
                    ClientSubjectHelper.getSubjectWithSectorIdentifier(
                            userProfile.get(),
                            configurationService.getInternalSectorUri(),
                            authenticationService);
            auditContext = auditContext.withSubjectId(internalCommonSubjectIdentifier.getValue());
            boolean hasValidCredentials =
                    authenticationService.login(
                            loginRequest.getEmail(), loginRequest.getPassword());
            if (!hasValidCredentials) {
                auditService.submitAuditEvent(
                        AUTH_ACCOUNT_MANAGEMENT_AUTHENTICATE_FAILURE,
                        auditContext,
                        AUDIT_EVENT_COMPONENT_ID_AUTH);
                return generateApiGatewayProxyErrorResponse(401, ErrorResponse.INVALID_LOGIN_CREDS);
            }

            if (configurationService.isAccountInterventionServiceCallInAuthenticateEnabled()) {
                try {
                    AccountInterventionsInboundResponse interventions =
                            accountInterventionsService.sendAccountInterventionsOutboundRequest(
                                    internalCommonSubjectIdentifier.getValue());

                    if (interventions.state().suspended()
                            && !interventions.state().resetPassword()
                            && !interventions.state().reproveIdentity()) {
                        auditService.submitAuditEvent(
                                AUTH_ACCOUNT_MANAGEMENT_AUTHENTICATE_INTERVENTION_FAILURE,
                                auditContext,
                                AUDIT_EVENT_COMPONENT_ID_AUTH);
                        LOG.info("Users account is suspended.");
                        return generateApiGatewayProxyErrorResponse(
                                403, ErrorResponse.ACCT_SUSPENDED);
                    }

                    if (interventions.state().blocked()) {
                        auditService.submitAuditEvent(
                                AUTH_ACCOUNT_MANAGEMENT_AUTHENTICATE_INTERVENTION_FAILURE,
                                auditContext,
                                AUDIT_EVENT_COMPONENT_ID_AUTH);
                        LOG.info("Users account is blocked.");
                        return generateApiGatewayProxyErrorResponse(
                                403, ErrorResponse.ACCT_BLOCKED);
                    }
                } catch (UnsuccessfulAccountInterventionsResponseException e) {
                    auditService.submitAuditEvent(
                            AUTH_ACCOUNT_MANAGEMENT_AUTHENTICATE_FAILURE,
                            auditContext,
                            AUDIT_EVENT_COMPONENT_ID_AUTH);
                    LOG.info("Request to Account Intervention Service failed.");
                    return generateApiGatewayProxyErrorResponse(
                            500, ErrorResponse.ACCT_INTERVENTIONS_UNEXPECTED_ERROR);
                }
            }
            LOG.info("User has successfully Logged in. Generating successful AuthenticateResponse");

            auditService.submitAuditEvent(
                    AUTH_ACCOUNT_MANAGEMENT_AUTHENTICATE,
                    auditContext,
                    AUDIT_EVENT_COMPONENT_ID_AUTH);

            return generateEmptySuccessApiGatewayResponse();
        } catch (JsonException e) {
            auditService.submitAuditEvent(
                    AUTH_ACCOUNT_MANAGEMENT_AUTHENTICATE_FAILURE,
                    auditContext,
                    AUDIT_EVENT_COMPONENT_ID_AUTH);
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.REQUEST_MISSING_PARAMS);
        }
    }
}

package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.AccountInterventionsInboundResponse;
import uk.gov.di.authentication.frontendapi.entity.AccountInterventionsRequest;
import uk.gov.di.authentication.frontendapi.entity.AccountInterventionsResponse;
import uk.gov.di.authentication.frontendapi.entity.State;
import uk.gov.di.authentication.frontendapi.services.AccountInterventionsService;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.exceptions.UnsuccessfulAccountInterventionsResponseException;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.lambda.BaseFrontendHandler;
import uk.gov.di.authentication.shared.serialization.Json.JsonException;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.Map;

import static com.nimbusds.oauth2.sdk.http.HTTPRequest.Method.GET;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.ConstructUriHelper.buildURI;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.AWS_REQUEST_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.PERSISTENT_SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachLogFieldToLogs;

public class AccountInterventionsHandler extends BaseFrontendHandler<AccountInterventionsRequest> {
    private static final Logger LOG = LogManager.getLogger(AccountInterventionsHandler.class);
    private final AccountInterventionsService accountInterventionsService;
    private final AuditService auditService;

    private static final Map<State, FrontendAuditableEvent>
            ACCOUNT_INTERVENTIONS_STATE_TO_AUDIT_EVENT =
                    Map.of(
                            new State(false, false, false, false),
                            FrontendAuditableEvent.NO_INTERVENTION,
                            new State(false, true, true, false),
                            FrontendAuditableEvent.NO_INTERVENTION,
                            new State(false, true, false, true),
                            FrontendAuditableEvent.PASSWORD_RESET_INTERVENTION,
                            new State(false, true, true, true),
                            FrontendAuditableEvent.PASSWORD_RESET_INTERVENTION,
                            new State(false, true, false, false),
                            FrontendAuditableEvent.TEMP_SUSPENDED_INTERVENTION,
                            new State(true, false, false, false),
                            FrontendAuditableEvent.PERMANENTLY_BLOCKED_INTERVENTION);

    protected AccountInterventionsHandler(
            ConfigurationService configurationService,
            SessionService sessionService,
            ClientSessionService clientSessionService,
            ClientService clientService,
            AuthenticationService authenticationService,
            AccountInterventionsService accountInterventionsService,
            AuditService auditService) {
        super(
                AccountInterventionsRequest.class,
                configurationService,
                sessionService,
                clientSessionService,
                clientService,
                authenticationService);
        this.accountInterventionsService = accountInterventionsService;
        this.auditService = auditService;
    }

    public AccountInterventionsHandler() {
        this(ConfigurationService.getInstance());
    }

    public AccountInterventionsHandler(ConfigurationService configurationService) {
        super(AccountInterventionsRequest.class, configurationService);
        accountInterventionsService = new AccountInterventionsService();
        this.auditService = new AuditService(configurationService);
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
            AccountInterventionsRequest request,
            UserContext userContext) {
        attachLogFieldToLogs(AWS_REQUEST_ID, context.getAwsRequestId());
        String persistentSessionID =
                PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders());
        attachLogFieldToLogs(PERSISTENT_SESSION_ID, persistentSessionID);
        LOG.info("Request received to the AccountInterventionsHandler");

        var userProfile = authenticationService.getUserProfileByEmailMaybe(request.email());
        if (userProfile.isEmpty()) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1049);
        }

        try {
            var internalPairwiseId =
                    ClientSubjectHelper.getSubjectWithSectorIdentifier(
                                    userProfile.get(),
                                    configurationService.getInternalSectorUri(),
                                    authenticationService)
                            .getValue();
            var accountInterventionsEndpoint =
                    configurationService.getAccountInterventionServiceURI().toString();
            var accountInterventionsURI =
                    buildURI(accountInterventionsEndpoint, "/v1/ais/" + internalPairwiseId);
            var accountInterventionsInboundRequest = new HTTPRequest(GET, accountInterventionsURI);
            var accountInterventionsInboundResponse =
                    accountInterventionsService.sendAccountInterventionsOutboundRequest(
                            accountInterventionsInboundRequest);

            logAisResponse(accountInterventionsInboundResponse);
            submitAuditEvents(
                    accountInterventionsInboundResponse, input, userContext, persistentSessionID);

            LOG.info("Generating Account Interventions outbound response for frontend");
            var accountInterventionsResponse =
                    new AccountInterventionsResponse(
                            accountInterventionsInboundResponse.state().resetPassword(),
                            accountInterventionsInboundResponse.state().blocked(),
                            accountInterventionsInboundResponse.state().suspended());
            return generateApiGatewayProxyResponse(200, accountInterventionsResponse, true);
        } catch (UnsuccessfulAccountInterventionsResponseException e) {
            LOG.error(
                    "Error in Account Interventions response HttpCode: {}, ErrorMessage: {}.",
                    e.getHttpCode(),
                    e.getMessage());
            if (e.getHttpCode() == 429) {
                return generateApiGatewayProxyErrorResponse(429, ErrorResponse.ERROR_1051);
            }
            if (e.getHttpCode() == 500) {
                return generateApiGatewayProxyErrorResponse(500, ErrorResponse.ERROR_1052);
            }
            if (e.getHttpCode() == 502) {
                return generateApiGatewayProxyErrorResponse(502, ErrorResponse.ERROR_1053);
            }
            if (e.getHttpCode() == 504) {
                return generateApiGatewayProxyErrorResponse(504, ErrorResponse.ERROR_1054);
            }
            return generateApiGatewayProxyErrorResponse(e.getHttpCode(), ErrorResponse.ERROR_1055);
        } catch (JsonException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        }
    }

    private void submitAuditEvents(
            AccountInterventionsInboundResponse accountInterventionsInboundResponse,
            APIGatewayProxyRequestEvent input,
            UserContext userContext,
            String persistentSessionID) {
        State requiredInterventionsState = accountInterventionsInboundResponse.state();

        FrontendAuditableEvent auditEvent =
                ACCOUNT_INTERVENTIONS_STATE_TO_AUDIT_EVENT.get(requiredInterventionsState);

        if (auditEvent != null) {
            auditService.submitAuditEvent(
                    auditEvent,
                    userContext.getClientSessionId(),
                    userContext.getSession().getSessionId(),
                    userContext.getClientId(),
                    userContext.getSession().getInternalCommonSubjectIdentifier(),
                    userContext.getSession().getEmailAddress(),
                    IpAddressHelper.extractIpAddress(input),
                    userContext
                            .getUserProfile()
                            .map(UserProfile::getPhoneNumber)
                            .orElse(AuditService.UNKNOWN),
                    persistentSessionID);
        } else {
            LOG.error(
                    "Unhandled account interventions state combination to calculate audit event: {}",
                    requiredInterventionsState);
        }
    }

    private void logAisResponse(
            AccountInterventionsInboundResponse accountInterventionsInboundResponse) {
        if (configurationService.isAisDetailedLoggingEnabled()) {
            LOG.info(
                    "AIS Response: blocked: {} suspended: {} resetPassword: {} reproveIdentity: {}",
                    accountInterventionsInboundResponse.state().blocked(),
                    accountInterventionsInboundResponse.state().suspended(),
                    accountInterventionsInboundResponse.state().resetPassword(),
                    accountInterventionsInboundResponse.state().reproveIdentity());
        }
    }
}

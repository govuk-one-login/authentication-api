package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.google.gson.Gson;
import com.google.gson.JsonIOException;
import com.google.gson.JsonSyntaxException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.entity.InternalTICFCRIRequest;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.AccountInterventionsInboundResponse;
import uk.gov.di.authentication.frontendapi.entity.AccountInterventionsRequest;
import uk.gov.di.authentication.frontendapi.entity.AccountInterventionsResponse;
import uk.gov.di.authentication.frontendapi.entity.State;
import uk.gov.di.authentication.frontendapi.services.AccountInterventionsService;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.exceptions.UnsuccessfulAccountInterventionsResponseException;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.NowHelper.NowClock;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.lambda.BaseFrontendHandler;
import uk.gov.di.authentication.shared.serialization.Json.JsonException;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.LambdaInvokerService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.time.Clock;
import java.util.ArrayList;
import java.util.Map;

import static java.lang.String.valueOf;
import static uk.gov.di.audit.AuditContext.auditContextFromUserContext;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.AWS_REQUEST_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.PERSISTENT_SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachLogFieldToLogs;

public class AccountInterventionsHandler extends BaseFrontendHandler<AccountInterventionsRequest> {
    private static final Logger LOG = LogManager.getLogger(AccountInterventionsHandler.class);
    private final AccountInterventionsService accountInterventionsService;
    private final AuditService auditService;
    private final CloudwatchMetricsService cloudwatchMetricsService;
    private final Gson gson;
    private final LambdaInvokerService lambdaInvoker;

    private final NowClock clock;

    private static final Map<State, FrontendAuditableEvent>
            ACCOUNT_INTERVENTIONS_STATE_TO_AUDIT_EVENT =
                    Map.ofEntries(
                            Map.entry(
                                    new State(false, false, false, false),
                                    FrontendAuditableEvent.AUTH_NO_INTERVENTION),
                            Map.entry(
                                    new State(false, true, true, false),
                                    FrontendAuditableEvent.AUTH_NO_INTERVENTION),
                            Map.entry(
                                    new State(false, true, false, true),
                                    FrontendAuditableEvent.AUTH_PASSWORD_RESET_INTERVENTION),
                            Map.entry(
                                    new State(false, true, true, true),
                                    FrontendAuditableEvent.AUTH_PASSWORD_RESET_INTERVENTION),
                            Map.entry(
                                    new State(false, true, false, false),
                                    FrontendAuditableEvent.AUTH_TEMP_SUSPENDED_INTERVENTION),
                            Map.entry(
                                    new State(true, false, false, false),
                                    FrontendAuditableEvent.AUTH_PERMANENTLY_BLOCKED_INTERVENTION));

    public AccountInterventionsHandler() {
        this(ConfigurationService.getInstance());
    }

    public AccountInterventionsHandler(ConfigurationService configurationService) {
        super(AccountInterventionsRequest.class, configurationService);
        accountInterventionsService = new AccountInterventionsService(configurationService);
        this.auditService = new AuditService(configurationService);
        this.cloudwatchMetricsService = new CloudwatchMetricsService(configurationService);
        this.clock = new NowClock(Clock.systemUTC());
        this.lambdaInvoker = new LambdaInvokerService(configurationService);
        gson = new Gson();
    }

    protected AccountInterventionsHandler(
            ConfigurationService configurationService,
            SessionService sessionService,
            ClientSessionService clientSessionService,
            ClientService clientService,
            AuthenticationService authenticationService,
            AccountInterventionsService accountInterventionsService,
            AuditService auditService,
            CloudwatchMetricsService cloudwatchMetricsService,
            NowClock clock,
            LambdaInvokerService lambdaInvoker,
            AuthSessionService authSessionService) {
        super(
                AccountInterventionsRequest.class,
                configurationService,
                sessionService,
                clientSessionService,
                clientService,
                authenticationService,
                authSessionService);
        this.accountInterventionsService = accountInterventionsService;
        this.auditService = auditService;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
        this.clock = clock;
        this.lambdaInvoker = lambdaInvoker;

        gson = new Gson();
    }

    public AccountInterventionsHandler(
            ConfigurationService configurationService,
            RedisConnectionService redis,
            LambdaInvokerService lambdaInvokerService) {
        super(AccountInterventionsRequest.class, configurationService, redis);

        this.lambdaInvoker = lambdaInvokerService;

        accountInterventionsService = new AccountInterventionsService(configurationService);
        this.auditService = new AuditService(configurationService);
        this.cloudwatchMetricsService = new CloudwatchMetricsService(configurationService);
        this.clock = new NowClock(Clock.systemUTC());
        gson = new Gson();
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return super.handleRequestWithoutClientSession(input, context);
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

        if (!configurationService.isAccountInterventionServiceCallEnabled()) {
            LOG.info(
                    "Account interventions service call is disabled, returning default no interventions response");
            try {
                return generateApiGatewayProxyResponse(200, noAccountInterventions(), true);
            } catch (JsonException e) {
                return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
            }
        }

        var userProfile = authenticationService.getUserProfileByEmailMaybe(request.email());

        if (userProfile.isEmpty()) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1049);
        }

        String internalPairwiseId =
                ClientSubjectHelper.getSubjectWithSectorIdentifier(
                                userProfile.get(),
                                configurationService.getInternalSectorUri(),
                                authenticationService)
                        .getValue();

        try {
            var accountInterventionsInboundResponse =
                    accountInterventionsService.sendAccountInterventionsOutboundRequest(
                            internalPairwiseId);

            logAisResponse(accountInterventionsInboundResponse);

            submitAuditEvents(
                    accountInterventionsInboundResponse, input, userContext, persistentSessionID);

            if (configurationService.isInvokeTicfCRILambdaEnabled()
                    && request.authenticated() != null) {
                AuthSessionItem authSession = userContext.getAuthSession();
                sendTICF(
                        userContext,
                        internalPairwiseId,
                        request.authenticated(),
                        authSession.getIsNewAccount(),
                        authSession.getResetPasswordState(),
                        authSession.getResetMfaState(),
                        authSession.getVerifiedMfaMethodType());
            }

            LOG.info("Generating Account Interventions outbound response for frontend");
            var accountInterventionsResponse =
                    getAccountInterventionsResponse(accountInterventionsInboundResponse);
            return generateApiGatewayProxyResponse(200, accountInterventionsResponse, true);
        } catch (UnsuccessfulAccountInterventionsResponseException e) {
            return handleErrorForAIS(e);
        } catch (JsonException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        }
    }

    private void sendTICF(
            UserContext userContext,
            String internalPairwiseId,
            boolean authenticated,
            AuthSessionItem.AccountState accountState,
            AuthSessionItem.ResetPasswordState resetPasswordState,
            AuthSessionItem.ResetMfaState resetMfaState,
            MFAMethodType verifiedMfaMethodType) {
        var vtr = new ArrayList<String>();

        try {
            vtr.add(
                    userContext
                            .getClientSession()
                            .getEffectiveVectorOfTrust()
                            .getCredentialTrustLevel()
                            .getValue());
        } catch (Exception e) {
            LOG.warn(
                    "Error retrieving effective vector of trust for TICF CRI Request: {}",
                    e.getMessage(),
                    e);
        }

        String journeyId = userContext.getClientSessionId();

        var ticfRequest =
                new InternalTICFCRIRequest(
                        internalPairwiseId,
                        vtr,
                        journeyId,
                        authenticated,
                        accountState,
                        resetPasswordState,
                        resetMfaState,
                        verifiedMfaMethodType);

        String payload;

        try {
            payload = gson.toJson(ticfRequest);
        } catch (JsonIOException | JsonSyntaxException | NullPointerException e) {
            LOG.error("Error serializing TICF CRI Request {}", e.getMessage(), e);
            return;
        } catch (Exception e) {
            LOG.error("Unexpected error serializing TICF CRI Request {}", e.getMessage(), e);
            return;
        }

        lambdaInvoker.invokeAsyncWithPayload(
                payload, configurationService.getTicfCRILambdaIdentifier());
    }

    private AccountInterventionsResponse getAccountInterventionsResponse(
            AccountInterventionsInboundResponse response) {
        var responseFromApi =
                new AccountInterventionsResponse(
                        response.state().resetPassword(),
                        response.state().blocked(),
                        response.state().suspended(),
                        response.state().reproveIdentity(),
                        response.intervention().appliedAt());
        incrementResultMetric(responseFromApi);
        if (!configurationService.accountInterventionsServiceActionEnabled()) {
            LOG.info(
                    "Account interventions action disabled, discarding response {} from api and returning no interventions",
                    responseFromApi);
            return noAccountInterventions();
        } else {
            return responseFromApi;
        }
    }

    private void incrementResultMetric(AccountInterventionsResponse response) {
        cloudwatchMetricsService.incrementCounter(
                "AuthAisResult",
                Map.of(
                        "Environment",
                        configurationService.getEnvironment(),
                        "blocked",
                        valueOf(response.blocked()),
                        "suspended",
                        valueOf(response.temporarilySuspended()),
                        "resetPassword",
                        valueOf(response.passwordResetRequired()),
                        "reproveIdentity",
                        valueOf(response.reproveIdentity())));
    }

    private APIGatewayProxyResponseEvent handleErrorForAIS(
            UnsuccessfulAccountInterventionsResponseException e) {
        cloudwatchMetricsService.incrementCounter(
                "Auth" + configurationService.getAccountInterventionsErrorMetricName(),
                Map.of("Environment", configurationService.getEnvironment()));
        LOG.error(
                "Error in Account Interventions response HttpCode: {}, ErrorMessage: {}.",
                e.getHttpCode(),
                e.getMessage());
        if (!configurationService.abortOnAccountInterventionsErrorResponse()
                || !configurationService.accountInterventionsServiceActionEnabled()) {
            try {
                LOG.error("Swallowing error and returning default account interventions response");
                cloudwatchMetricsService.incrementCounter(
                        "AuthAisErrorIgnored",
                        Map.of("Environment", configurationService.getEnvironment()));
                return generateApiGatewayProxyResponse(200, noAccountInterventions(), true);
            } catch (JsonException ex) {
                return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
            }
        }
        return switch (e.getHttpCode()) {
            case 429 -> generateApiGatewayProxyErrorResponse(429, ErrorResponse.ERROR_1051);
            case 500 -> generateApiGatewayProxyErrorResponse(500, ErrorResponse.ERROR_1052);
            case 502 -> generateApiGatewayProxyErrorResponse(502, ErrorResponse.ERROR_1053);
            case 504 -> generateApiGatewayProxyErrorResponse(504, ErrorResponse.ERROR_1054);
            default -> generateApiGatewayProxyErrorResponse(
                    e.getHttpCode(), ErrorResponse.ERROR_1055);
        };
    }

    private void submitAuditEvents(
            AccountInterventionsInboundResponse accountInterventionsInboundResponse,
            APIGatewayProxyRequestEvent input,
            UserContext userContext,
            String persistentSessionID) {
        State requiredInterventionsState = accountInterventionsInboundResponse.state();

        FrontendAuditableEvent auditEvent =
                ACCOUNT_INTERVENTIONS_STATE_TO_AUDIT_EVENT.get(requiredInterventionsState);

        var auditContext =
                auditContextFromUserContext(
                        userContext,
                        userContext.getAuthSession().getInternalCommonSubjectId(),
                        userContext.getAuthSession().getEmailAddress(),
                        IpAddressHelper.extractIpAddress(input),
                        userContext
                                .getUserProfile()
                                .map(UserProfile::getPhoneNumber)
                                .orElse(AuditService.UNKNOWN),
                        persistentSessionID);

        if (auditEvent != null) {
            auditService.submitAuditEvent(auditEvent, auditContext);
        } else {
            LOG.error(
                    "Unhandled account interventions state combination to calculate audit event: {}",
                    requiredInterventionsState);
        }
    }

    private void logAisResponse(
            AccountInterventionsInboundResponse accountInterventionsInboundResponse) {
        LOG.info("AIS Response: {}", accountInterventionsInboundResponse.state());
    }

    private AccountInterventionsResponse noAccountInterventions() {
        return new AccountInterventionsResponse(
                false, false, false, false, clock.now().toInstant().toEpochMilli());
    }
}

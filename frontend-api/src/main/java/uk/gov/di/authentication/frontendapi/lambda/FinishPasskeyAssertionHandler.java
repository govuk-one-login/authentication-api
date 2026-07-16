package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.yubico.webauthn.AssertionResult;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.auditevents.services.StructuredAuditService;
import uk.gov.di.authentication.frontendapi.entity.FinishPasskeyAssertionFailureReason;
import uk.gov.di.authentication.frontendapi.entity.FinishPasskeyAssertionRequest;
import uk.gov.di.authentication.frontendapi.services.passkeys.PasskeysService;
import uk.gov.di.authentication.frontendapi.services.webauthn.DefaultPasskeyJsonParser;
import uk.gov.di.authentication.frontendapi.services.webauthn.PasskeyAssertionService;
import uk.gov.di.authentication.frontendapi.services.webauthn.RelyingPartyProvider;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.lambda.BaseFrontendHandler;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.state.UserContext;
import uk.gov.di.authentication.userpermissions.UserActionsManager;
import uk.gov.di.authentication.userpermissions.entity.PermissionContext;

import java.time.Clock;
import java.util.Map;

import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.ENVIRONMENT;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.FAILURE_REASON;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetrics.PASSKEY_AUTHENTICATION_SUCCESSFUL;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetrics.PASSKEY_VERIFICATION_FAILED;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetrics.PASSKEY_VERIFICATION_SUCCESSFUL;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;

public class FinishPasskeyAssertionHandler
        extends BaseFrontendHandler<FinishPasskeyAssertionRequest>
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private static final Logger LOG = LogManager.getLogger(FinishPasskeyAssertionHandler.class);
    private final PasskeyAssertionService passkeyAssertionService;
    private final UserActionsManager userActionsManager;
    private final CloudwatchMetricsService cloudwatchMetricsService;
    private final PasskeysService passkeysService;

    public FinishPasskeyAssertionHandler() {
        this(ConfigurationService.getInstance());
    }

    public FinishPasskeyAssertionHandler(
            ConfigurationService configurationService,
            AuthenticationService authenticationService,
            AuthSessionService authSessionService,
            PasskeyAssertionService passkeyAssertionService,
            UserActionsManager userActionsManager,
            CloudwatchMetricsService cloudwatchMetricsService,
            PasskeysService passkeysService) {
        super(
                FinishPasskeyAssertionRequest.class,
                configurationService,
                authenticationService,
                authSessionService);
        this.passkeyAssertionService = passkeyAssertionService;
        this.userActionsManager = userActionsManager;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
        this.passkeysService = passkeysService;
    }

    public FinishPasskeyAssertionHandler(ConfigurationService configurationService) {
        super(FinishPasskeyAssertionRequest.class, configurationService);
        this.passkeyAssertionService =
                new PasskeyAssertionService(
                        RelyingPartyProvider.provide(configurationService),
                        new DefaultPasskeyJsonParser(),
                        new StructuredAuditService(configurationService));
        this.userActionsManager = new UserActionsManager(configurationService);
        this.cloudwatchMetricsService = new CloudwatchMetricsService(configurationService);
        this.passkeysService = new PasskeysService(configurationService);
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
            FinishPasskeyAssertionRequest request,
            UserContext userContext) {

        LOG.info("FinishPasskeyAssertionHandler called");

        reportPasskeyAuthenticationSuccess();

        return verifyPasskeyAssertion(userContext, request, input)
                .flatMap(assertionResult -> updatePasskeyRecord(assertionResult, userContext))
                .tap(success -> reportCorrectPasskeyReceived(userContext))
                .tapFailure(failure -> reportIncorrectPasskeyReceived(userContext, failure))
                .fold(
                        failure ->
                                switch (failure) {
                                    case PARSING_ASSERTION_REQUEST_ERROR -> generateApiGatewayProxyErrorResponse(
                                            500, ErrorResponse.UNEXPECTED_INTERNAL_API_ERROR);
                                    case PARSING_PKC_ERROR -> generateApiGatewayProxyErrorResponse(
                                            400, ErrorResponse.PASSKEY_ASSERTION_INVALID_PKC);
                                    case ASSERTION_FAILED_ERROR -> generateApiGatewayProxyErrorResponse(
                                            401, ErrorResponse.PASSKEY_ASSERTION_FAILED);
                                },
                        success -> generateApiGatewayProxyResponse(200, ""));
    }

    private void reportPasskeyAuthenticationSuccess() {
        var metricsDimensions =
                Map.of(ENVIRONMENT.getValue(), configurationService.getEnvironment());
        cloudwatchMetricsService.incrementCounter(
                PASSKEY_AUTHENTICATION_SUCCESSFUL, metricsDimensions);
    }

    private Result<FinishPasskeyAssertionFailureReason, AssertionResult> verifyPasskeyAssertion(
            UserContext userContext,
            FinishPasskeyAssertionRequest request,
            APIGatewayProxyRequestEvent input) {
        var auditContext =
                AuditContext.auditContextFromUserContext(
                        userContext,
                        userContext.getAuthSession().getInternalCommonSubjectId(),
                        userContext.getAuthSession().getEmailAddress(),
                        IpAddressHelper.extractIpAddress(input),
                        AuditService.UNKNOWN,
                        PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders()));
        var publicSubjectId =
                userContext.getUserProfile().map(UserProfile::getPublicSubjectID).orElse(null);
        return passkeyAssertionService.finishAssertion(
                userContext.getAuthSession().getPasskeyAssertionRequest(),
                request.pkc(),
                auditContext,
                publicSubjectId);
    }

    private Result<FinishPasskeyAssertionFailureReason, Void> updatePasskeyRecord(
            AssertionResult assertionResult, UserContext userContext) {
        var publicSubjectId = userContext.getUserProfile().get().getPublicSubjectID();
        var sessionId = userContext.getAuthSession().getSessionId();
        var passkeyId = assertionResult.getCredential().getCredentialId().getBase64Url();
        var signCount = assertionResult.getSignatureCount();
        var result =
                passkeysService.updatePasskey(
                        publicSubjectId, sessionId, passkeyId, signCount, Clock.systemUTC());
        if (result.isFailure()) {
            throw new RuntimeException("TODO");
        }
        return Result.success(null);
    }

    private Void reportCorrectPasskeyReceived(UserContext userContext) {
        PermissionContext permissionContext =
                PermissionContext.builder()
                        .withAuthSessionItem(userContext.getAuthSession())
                        .build();
        userActionsManager.correctPasskeyReceived(null, permissionContext);

        var metricsDimensions =
                Map.of(ENVIRONMENT.getValue(), configurationService.getEnvironment());
        cloudwatchMetricsService.incrementCounter(
                PASSKEY_VERIFICATION_SUCCESSFUL, metricsDimensions);

        return null;
    }

    private Void reportIncorrectPasskeyReceived(
            UserContext userContext, FinishPasskeyAssertionFailureReason failureReason) {
        PermissionContext permissionContext =
                PermissionContext.builder()
                        .withAuthSessionItem(userContext.getAuthSession())
                        .build();
        userActionsManager.incorrectPasskeyReceived(null, permissionContext);

        var metricsDimensions =
                Map.ofEntries(
                        Map.entry(ENVIRONMENT.getValue(), configurationService.getEnvironment()),
                        Map.entry(FAILURE_REASON.getValue(), failureReason.getValue()));
        cloudwatchMetricsService.incrementCounter(PASSKEY_VERIFICATION_FAILED, metricsDimensions);

        return null;
    }
}

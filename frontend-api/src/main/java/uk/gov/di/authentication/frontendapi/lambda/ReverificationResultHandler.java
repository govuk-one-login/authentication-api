package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import net.minidev.json.JSONObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.frontendapi.entity.IpvReverificationFailureCode;
import uk.gov.di.authentication.frontendapi.entity.ReverificationResultRequest;
import uk.gov.di.authentication.frontendapi.services.ReverificationResultService;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.exceptions.UnsuccessfulReverificationResponseException;
import uk.gov.di.authentication.shared.helpers.ConstructUriHelper;
import uk.gov.di.authentication.shared.helpers.InstrumentationHelper;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.lambda.BaseFrontendHandler;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.IDReverificationStateService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.ArrayList;
import java.util.List;

import static uk.gov.di.audit.AuditContext.auditContextFromUserContext;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_REVERIFY_SUCCESSFUL_TOKEN_RECEIVED;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_REVERIFY_VERIFICATION_INFO_RECEIVED;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1058;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1059;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1061;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;

public class ReverificationResultHandler extends BaseFrontendHandler<ReverificationResultRequest>
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private static final Logger LOG = LogManager.getLogger(ReverificationResultHandler.class);
    public static final String IPV_REVERIFICATION_SUCCESS = "success";
    public static final String IPV_REVERIFICATION_FAILURE_CODE = "failure_code";
    private final ReverificationResultService reverificationResultService;
    private final AuditService auditService;
    private final IDReverificationStateService idReverificationStateService;
    private final CloudwatchMetricsService cloudwatchMetricService;

    public ReverificationResultHandler(
            ConfigurationService configurationService,
            SessionService sessionService,
            ClientService clientService,
            AuthenticationService authenticationService,
            ReverificationResultService reverificationResultService,
            AuditService auditService,
            AuthSessionService authSessionService,
            IDReverificationStateService idReverificationStateService,
            CloudwatchMetricsService cloudwatchMetricsService) {
        super(
                ReverificationResultRequest.class,
                configurationService,
                sessionService,
                clientService,
                authenticationService,
                authSessionService);
        this.reverificationResultService = reverificationResultService;
        this.auditService = auditService;
        this.idReverificationStateService = idReverificationStateService;
        this.cloudwatchMetricService = cloudwatchMetricsService;
    }

    public ReverificationResultHandler() {
        this(ConfigurationService.getInstance());
    }

    public ReverificationResultHandler(RedisConnectionService redisConnectionService) {
        super(
                ReverificationResultRequest.class,
                ConfigurationService.getInstance(),
                redisConnectionService);
        this.reverificationResultService = new ReverificationResultService(configurationService);
        this.auditService = new AuditService(configurationService);
        this.idReverificationStateService = new IDReverificationStateService(configurationService);
        this.cloudwatchMetricService = new CloudwatchMetricsService(configurationService);
    }

    public ReverificationResultHandler(ConfigurationService configurationService) {
        super(ReverificationResultRequest.class, configurationService, true);
        this.reverificationResultService = new ReverificationResultService(configurationService);
        this.auditService = new AuditService(configurationService);
        this.idReverificationStateService = new IDReverificationStateService(configurationService);
        this.cloudwatchMetricService = new CloudwatchMetricsService(configurationService);
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
            ReverificationResultRequest request,
            UserContext userContext) {

        var baseAuditContext =
                auditContextFromUserContext(
                        userContext,
                        userContext.getAuthSession().getInternalCommonSubjectId(),
                        request.email(),
                        IpAddressHelper.extractIpAddress(input),
                        userContext
                                .getUserProfile()
                                .map(UserProfile::getPhoneNumber)
                                .orElse(AuditService.UNKNOWN),
                        PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders()));

        var idReverificationStateMaybe = idReverificationStateService.get(request.state());
        if (idReverificationStateMaybe.isEmpty()) {
            LOG.error("Cannot match received state to a recorded state");
            return generateApiGatewayProxyErrorResponse(400, ERROR_1061);
        }

        var idReverificationState = idReverificationStateMaybe.get();
        if (!idReverificationState.getClientSessionId().equals(userContext.getClientSessionId())) {
            LOG.error("Received state belongs to a different session");
            return generateApiGatewayProxyErrorResponse(400, ERROR_1061);
        }

        var tokenResponse =
                InstrumentationHelper.segmentedFunctionCall(
                        "getIpvToken", () -> reverificationResultService.getToken(request.code()));

        if (!tokenResponse.indicatesSuccess()) {
            LOG.error(
                    "IPV TokenResponse was not successful: {}",
                    tokenResponse.toErrorResponse().toJSONObject());
            return generateApiGatewayProxyErrorResponse(400, ERROR_1058);
        }
        LOG.info("Successful IPV TokenResponse");

        var metadataPairs = new ArrayList<AuditService.MetadataPair>();
        metadataPairs.add(
                AuditService.MetadataPair.pair(
                        "journey-type", JourneyType.ACCOUNT_RECOVERY.getValue()));

        auditService.submitAuditEvent(
                AUTH_REVERIFY_SUCCESSFUL_TOKEN_RECEIVED,
                baseAuditContext,
                metadataPairs.toArray(AuditService.MetadataPair[]::new));

        try {
            var reverificationResult =
                    reverificationResultService.sendIpvReverificationRequest(
                            new UserInfoRequest(
                                    ConstructUriHelper.buildURI(
                                            configurationService.getIPVBackendURI().toString(),
                                            "reverification"),
                                    tokenResponse
                                            .toSuccessResponse()
                                            .getTokens()
                                            .getBearerAccessToken()));

            LOG.info("ReverificationResult response received from IPV");

            var reverificationResultJson = reverificationResult.getContentAsJSONObject();

            var validMetadata =
                    extractValidMetadata(
                            reverificationResultJson,
                            userContext.getAuthSession().getInternalCommonSubjectId());

            metadataPairs.addAll(validMetadata.metadataPairs());

            auditService.submitAuditEvent(
                    AUTH_REVERIFY_VERIFICATION_INFO_RECEIVED,
                    baseAuditContext,
                    metadataPairs.toArray(AuditService.MetadataPair[]::new));

            if (!validMetadata.valid()) {
                LOG.warn(validMetadata.errorMessage());
                var logFriendlyResponse = reverificationResultJson.toJSONString();
                LOG.warn(
                        "Invalid re-verification result response from IPV: {}",
                        logFriendlyResponse);
                return generateApiGatewayProxyErrorResponse(400, ERROR_1059);
            }

            return generateApiGatewayProxyResponse(200, reverificationResult.getContent());
        } catch (UnsuccessfulReverificationResponseException | ParseException e) {
            LOG.error("Error getting reverification result", e);
            return generateApiGatewayProxyErrorResponse(400, ERROR_1059);
        }
    }

    private ValidationResult extractValidMetadata(JSONObject json, String sub) {
        List<AuditService.MetadataPair> metadataPairs = new ArrayList<>();

        if (!json.containsKey("sub") || !(json.get("sub") instanceof String subOfResponse)) {
            return ValidationResult.failure(
                    "Missing sub cannot verify response is for current user.", metadataPairs);
        }

        if (!sub.equalsIgnoreCase(subOfResponse)) {
            return ValidationResult.failure("sub does not match current user.", metadataPairs);
        }

        if (!json.containsKey(IPV_REVERIFICATION_SUCCESS)
                || !(json.get(IPV_REVERIFICATION_SUCCESS) instanceof Boolean)) {
            metadataPairs.add(
                    AuditService.MetadataPair.pair(
                            IPV_REVERIFICATION_SUCCESS, "missing or corrupt"));
            return ValidationResult.failure("Invalid or missing 'success' field.", metadataPairs);
        }

        boolean success = (boolean) json.get(IPV_REVERIFICATION_SUCCESS);

        metadataPairs.add(AuditService.MetadataPair.pair(IPV_REVERIFICATION_SUCCESS, success));

        if (success
                && (json.containsKey(IPV_REVERIFICATION_FAILURE_CODE)
                        || json.containsKey("failure_reason"))) {
            metadataPairs.add(
                    AuditService.MetadataPair.pair(
                            IPV_REVERIFICATION_FAILURE_CODE,
                            json.get(IPV_REVERIFICATION_FAILURE_CODE)));
            return ValidationResult.failure(
                    "'failure_code' or 'failure_reason' must not be present when successful.",
                    metadataPairs);
        }

        if (!success) {
            boolean failureDetailsMissing =
                    !json.containsKey(IPV_REVERIFICATION_FAILURE_CODE)
                            || !(json.get(IPV_REVERIFICATION_FAILURE_CODE) instanceof String);

            if (failureDetailsMissing) {
                return ValidationResult.failure("Invalid or missing 'failure_code'", metadataPairs);
            }

            String failValue = (String) json.get(IPV_REVERIFICATION_FAILURE_CODE);

            if (!IpvReverificationFailureCode.isValid(failValue)) {
                metadataPairs.add(
                        AuditService.MetadataPair.pair(IPV_REVERIFICATION_FAILURE_CODE, failValue));
                return ValidationResult.failure(
                        "Invalid or missing 'failure_reason'", metadataPairs);
            }
            LOG.info("Received reverification failure code due to {}", failValue);
            cloudwatchMetricService.incrementMfaResetIpvResponseCount(failValue);
            metadataPairs.add(
                    AuditService.MetadataPair.pair(IPV_REVERIFICATION_FAILURE_CODE, failValue));
        } else {
            LOG.info("Received reverification success code");
            cloudwatchMetricService.incrementMfaResetIpvResponseCount(IPV_REVERIFICATION_SUCCESS);
        }
        return ValidationResult.success(metadataPairs);
    }
}

record ValidationResult(
        boolean valid, String errorMessage, List<AuditService.MetadataPair> metadataPairs) {

    public static ValidationResult success(List<AuditService.MetadataPair> metadataPairs) {
        return new ValidationResult(true, null, metadataPairs);
    }

    public static ValidationResult failure(
            String errorMessage, List<AuditService.MetadataPair> metadataPairs) {
        return new ValidationResult(false, errorMessage, metadataPairs);
    }
}

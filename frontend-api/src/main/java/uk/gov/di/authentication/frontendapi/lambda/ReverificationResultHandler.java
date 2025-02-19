package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
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
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.IDReverificationStateService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.ArrayList;

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
    private final ReverificationResultService reverificationResultService;
    private final AuditService auditService;
    private final IDReverificationStateService idReverificationStateService;
    private final CloudwatchMetricsService cloudwatchMetricService;

    public ReverificationResultHandler(
            ConfigurationService configurationService,
            SessionService sessionService,
            ClientSessionService clientSessionService,
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
                clientSessionService,
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

        var auditContext =
                auditContextFromUserContext(
                        userContext,
                        userContext.getSession().getInternalCommonSubjectIdentifier(),
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
        auditService.submitAuditEvent(
                AUTH_REVERIFY_SUCCESSFUL_TOKEN_RECEIVED,
                auditContext,
                AuditService.MetadataPair.pair(
                        "journey-type", JourneyType.ACCOUNT_RECOVERY.getValue()));

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
            var success = reverificationResultJson.get("success");
            var failureCode = reverificationResultJson.get("failure_code");

            var metadataPairs = new ArrayList<AuditService.MetadataPair>();
            metadataPairs.add(
                    AuditService.MetadataPair.pair(
                            "journey-type", JourneyType.ACCOUNT_RECOVERY.getValue()));
            metadataPairs.add(AuditService.MetadataPair.pair("success", success));
            if (failureCode != null) {
                try {
                    var parsedFailureCode =
                            IpvReverificationFailureCode.fromValue(failureCode.toString());
                    metadataPairs.add(
                            AuditService.MetadataPair.pair(
                                    "failure_code", parsedFailureCode.getValue()));
                    cloudwatchMetricService.incrementMfaResetIpvResponseCount(
                            parsedFailureCode.getValue());
                } catch (IllegalArgumentException e) {
                    LOG.warn("Unknown ipv reverification failure code of {}", failureCode);
                }
            }

            if (success == null) {
                return generateApiGatewayProxyErrorResponse(400, ERROR_1059);
            }
            if (success.equals(true)) {
                cloudwatchMetricService.incrementMfaResetIpvResponseCount("success");
            }

            auditService.submitAuditEvent(
                    AUTH_REVERIFY_VERIFICATION_INFO_RECEIVED,
                    auditContext,
                    metadataPairs.toArray(AuditService.MetadataPair[]::new));

            return generateApiGatewayProxyResponse(200, reverificationResult.getContent());
        } catch (UnsuccessfulReverificationResponseException | ParseException e) {
            LOG.error("Error getting reverification result", e);
            return generateApiGatewayProxyErrorResponse(400, ERROR_1059);
        }
    }
}

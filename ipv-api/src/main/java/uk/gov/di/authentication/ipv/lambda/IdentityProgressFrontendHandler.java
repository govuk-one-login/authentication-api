package uk.gov.di.authentication.ipv.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.ipv.domain.IPVAuditableEvent;
import uk.gov.di.authentication.ipv.entity.IdentityProgressResponse;
import uk.gov.di.authentication.ipv.entity.IdentityProgressStatus;
import uk.gov.di.orchestration.audit.TxmaAuditUser;
import uk.gov.di.orchestration.shared.entity.ErrorResponse;
import uk.gov.di.orchestration.shared.lambda.BaseOrchestrationFrontendHandler;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.services.AuditService;
import uk.gov.di.orchestration.shared.services.AuthenticationUserInfoStorageService;
import uk.gov.di.orchestration.shared.services.CloudwatchMetricsService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.DynamoIdentityService;
import uk.gov.di.orchestration.shared.services.OrchClientSessionService;
import uk.gov.di.orchestration.shared.services.OrchSessionService;
import uk.gov.di.orchestration.shared.services.SessionService;
import uk.gov.di.orchestration.shared.state.OrchestrationUserSession;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import static uk.gov.di.orchestration.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.orchestration.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.orchestration.shared.helpers.IpAddressHelper.extractIpAddress;
import static uk.gov.di.orchestration.shared.helpers.PersistentIdHelper.extractPersistentIdFromHeaders;

public class IdentityProgressFrontendHandler extends BaseOrchestrationFrontendHandler {
    private final DynamoIdentityService dynamoIdentityService;
    private final AuditService auditService;
    private final CloudwatchMetricsService cloudwatchMetricsService;
    private final AuthenticationUserInfoStorageService userInfoStorageService;

    private static final Logger LOG = LogManager.getLogger(IdentityProgressFrontendHandler.class);

    public IdentityProgressFrontendHandler(ConfigurationService configurationService) {
        super(configurationService);
        this.dynamoIdentityService = new DynamoIdentityService(configurationService);
        this.auditService = new AuditService(configurationService);
        this.cloudwatchMetricsService = new CloudwatchMetricsService();
        this.userInfoStorageService =
                new AuthenticationUserInfoStorageService(configurationService);
    }

    public IdentityProgressFrontendHandler() {
        this(ConfigurationService.getInstance());
    }

    public IdentityProgressFrontendHandler(
            ConfigurationService configurationService,
            DynamoIdentityService dynamoIdentityService,
            AuditService auditService,
            CloudwatchMetricsService cloudwatchMetricsService,
            SessionService sessionService,
            AuthenticationUserInfoStorageService userInfoStorageService,
            OrchSessionService orchSessionService,
            OrchClientSessionService orchClientSessionService) {
        super(configurationService, sessionService, orchSessionService, orchClientSessionService);
        this.dynamoIdentityService = dynamoIdentityService;
        this.auditService = auditService;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
        this.userInfoStorageService = userInfoStorageService;
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return super.handleRequest(input, context);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequestWithUserSession(
            APIGatewayProxyRequestEvent input,
            Context context,
            OrchestrationUserSession userSession) {
        LOG.info("IdentityProgress request received");
        try {
            var internalCommonSubjectIdentifier =
                    userSession.getOrchSession().getInternalCommonSubjectId();

            AuthenticationRequest authenticationRequest;
            try {
                if (Objects.isNull(userSession.getOrchClientSession())) {
                    LOG.info("ClientSession not found");
                    return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1018);
                }
                authenticationRequest =
                        AuthenticationRequest.parse(
                                userSession.getOrchClientSession().getAuthRequestParams());
            } catch (ParseException e) {
                LOG.warn("Authentication request could not be parsed", e);
                return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1038);
            }

            UserInfo userInfo;

            if (Objects.isNull(internalCommonSubjectIdentifier)
                    || internalCommonSubjectIdentifier.isBlank()) {
                LOG.warn("InternalCommonSubjectId is null on orch session");
                return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1000);
            }
            try {
                Optional<UserInfo> userInfoFromStorage =
                        userInfoStorageService.getAuthenticationUserInfo(
                                internalCommonSubjectIdentifier, userSession.getClientSessionId());

                if (userInfoFromStorage.isEmpty()) {
                    LOG.warn("Unable to find user info for subject");
                    return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1000);
                }

                userInfo = userInfoFromStorage.get();
            } catch (ParseException e) {
                LOG.warn("Error finding user info for subject");
                return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1000);
            }

            var pairwiseSubjectId = (String) userInfo.getClaim("rp_pairwise_id");

            int processingIdentityAttempts =
                    userSession.getOrchSession().incrementProcessingIdentityAttempts();
            LOG.info(
                    "Attempting to find identity credentials in dynamo. Attempt: {}",
                    processingIdentityAttempts);
            var identityCredentials =
                    dynamoIdentityService.getIdentityCredentials(userSession.getClientSessionId());

            var processingStatus = IdentityProgressStatus.PROCESSING;
            if (identityCredentials.isEmpty()
                    && userSession.getOrchSession().getProcessingIdentityAttempts() == 1) {
                processingStatus = IdentityProgressStatus.NO_ENTRY;
                userSession.getOrchSession().resetProcessingIdentityAttempts();
            } else if (identityCredentials.isEmpty()) {
                processingStatus = IdentityProgressStatus.ERROR;
            } else if (Objects.nonNull(identityCredentials.get().getCoreIdentityJWT())) {
                processingStatus = IdentityProgressStatus.COMPLETED;
            }

            cloudwatchMetricsService.incrementCounter(
                    "ProcessingIdentity",
                    Map.of(
                            "Environment",
                            configurationService.getEnvironment(),
                            "Status",
                            processingStatus.toString()));

            var user =
                    TxmaAuditUser.user()
                            .withGovukSigninJourneyId(userSession.getClientSessionId())
                            .withSessionId(userSession.getSessionId())
                            .withIpAddress(extractIpAddress(input))
                            .withPersistentSessionId(
                                    extractPersistentIdFromHeaders(input.getHeaders()));

            auditService.submitAuditEvent(
                    IPVAuditableEvent.PROCESSING_IDENTITY_REQUEST,
                    Optional.of(userSession)
                            .map(OrchestrationUserSession::getClientId)
                            .orElse(AuditService.UNKNOWN),
                    user);

            orchSessionService.updateSession(userSession.getOrchSession());

            LOG.info(
                    "Generating IdentityProgressResponse with IdentityProgressStatus: {}",
                    processingStatus);
            return generateApiGatewayProxyResponse(
                    200,
                    new IdentityProgressResponse(
                            processingStatus,
                            userSession.getOrchClientSession().getClientName(),
                            authenticationRequest.getRedirectionURI(),
                            authenticationRequest.getState()));
        } catch (Json.JsonException e) {
            LOG.error("Unable to generate IdentityProgressResponse");
            throw new RuntimeException();
        }
    }

    @Override
    protected String getSegmentName() {
        return "ipv-api::";
    }
}

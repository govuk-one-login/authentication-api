package uk.gov.di.authentication.ipv.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.ipv.domain.IPVAuditableEvent;
import uk.gov.di.authentication.ipv.entity.IdentityProgressResponse;
import uk.gov.di.authentication.ipv.entity.IdentityProgressStatus;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.lambda.BaseOrchestrationHandler;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationUserInfoStorageService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoIdentityService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.state.OrchestrationUserSession;

import java.util.Map;
import java.util.Objects;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;

public class IdentityProgressHandler extends BaseOrchestrationHandler {
    private final DynamoIdentityService dynamoIdentityService;
    private final AuditService auditService;
    private final CloudwatchMetricsService cloudwatchMetricsService;
    private final AuthenticationUserInfoStorageService userInfoStorageService;

    private static final Logger LOG = LogManager.getLogger(ProcessingIdentityHandler.class);

    public IdentityProgressHandler(ConfigurationService configurationService) {
        super(configurationService);
        this.dynamoIdentityService = new DynamoIdentityService(configurationService);
        this.auditService = new AuditService(configurationService);
        this.cloudwatchMetricsService = new CloudwatchMetricsService();
        this.userInfoStorageService =
                new AuthenticationUserInfoStorageService(configurationService);
    }

    public IdentityProgressHandler() {
        this(ConfigurationService.getInstance());
    }

    public IdentityProgressHandler(
            ConfigurationService configurationService,
            DynamoIdentityService dynamoIdentityService,
            AuditService auditService,
            CloudwatchMetricsService cloudwatchMetricsService,
            SessionService sessionService,
            AuthenticationUserInfoStorageService userInfoStorageService,
            ClientSessionService clientSessionService) {
        super(configurationService, sessionService, clientSessionService);
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
                    userSession.getSession().getInternalCommonSubjectIdentifier();

            AuthenticationRequest authenticationRequest;
            try {
                if (Objects.isNull(userSession.getClientSession())) {
                    LOG.info("ClientSession not found");
                    return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1018);
                }
                authenticationRequest =
                        AuthenticationRequest.parse(
                                userSession.getClientSession().getAuthRequestParams());
            } catch (ParseException e) {
                LOG.warn("Authentication request could not be parsed", e);
                return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1038);
            }

            UserInfo userInfo;
            try {
                var authenticationUserInfo =
                        userInfoStorageService.getAuthenticationUserInfoData(
                                internalCommonSubjectIdentifier);

                if (authenticationUserInfo.isPresent()) {
                    userInfo =
                            new UserInfo(
                                    JSONObjectUtils.parse(
                                            authenticationUserInfo.get().getUserInfo()));
                } else {
                    return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1000);
                }
            } catch (Exception e) {
                return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1000);
            }
            var pairwiseSubjectId = (String) userInfo.getClaim("rp_pairwise_id");

            int processingAttempts = userSession.getSession().incrementProcessingIdentityAttempts();
            LOG.info(
                    "Attempting to find identity credentials in dynamo. Attempt: {}",
                    processingAttempts);
            var identityCredentials =
                    dynamoIdentityService.getIdentityCredentials(pairwiseSubjectId);

            var processingStatus = IdentityProgressStatus.PROCESSING;
            if (identityCredentials.isEmpty()
                    && userSession.getSession().getProcessingIdentityAttempts() == 1) {
                processingStatus = IdentityProgressStatus.NO_ENTRY;
                userSession.getSession().resetProcessingIdentityAttempts();
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

            auditService.submitAuditEvent(
                    IPVAuditableEvent.PROCESSING_IDENTITY_REQUEST,
                    userSession.getClientSessionId(),
                    userSession.getSession().getSessionId(),
                    userSession.getClientId() != null
                            ? userSession.getClientId()
                            : AuditService.UNKNOWN,
                    AuditService.UNKNOWN,
                    AuditService.UNKNOWN,
                    IpAddressHelper.extractIpAddress(input),
                    AuditService.UNKNOWN,
                    PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders()));

            sessionService.save(userSession.getSession());

            LOG.info(
                    "Generating IdentityProgressResponse with IdentityProgressStatus: {}",
                    processingStatus);
            return generateApiGatewayProxyResponse(
                    200,
                    new IdentityProgressResponse(
                            processingStatus,
                            userSession.getClientSession().getClientName(),
                            authenticationRequest.getRedirectionURI(),
                            authenticationRequest.getState()));
        } catch (Json.JsonException e) {
            LOG.error("Unable to generate IdentityProgressResponse");
            throw new RuntimeException();
        }
    }
}

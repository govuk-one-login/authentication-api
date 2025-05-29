package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationSuccessResponse;
import com.nimbusds.oauth2.sdk.id.State;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.frontendapi.entity.AuthCodeRequest;
import uk.gov.di.authentication.frontendapi.entity.AuthCodeResponse;
import uk.gov.di.authentication.frontendapi.helpers.ReauthMetadataBuilder;
import uk.gov.di.authentication.shared.domain.CloudwatchMetrics;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.lambda.BaseFrontendHandler;
import uk.gov.di.authentication.shared.serialization.Json.JsonException;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoAuthCodeService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.net.URI;
import java.util.Map;

import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_REAUTH_SUCCESS;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.ENVIRONMENT;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.AWS_REQUEST_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachLogFieldToLogs;

public class AuthenticationAuthCodeHandler extends BaseFrontendHandler<AuthCodeRequest> {

    private static final Logger LOG = LogManager.getLogger(AuthenticationAuthCodeHandler.class);

    private final DynamoAuthCodeService dynamoAuthCodeService;
    private final AuditService auditService;
    private final CloudwatchMetricsService cloudwatchMetricsService;

    public AuthenticationAuthCodeHandler(
            DynamoAuthCodeService dynamoAuthCodeService,
            ConfigurationService configurationService,
            SessionService sessionService,
            ClientService clientService,
            AuthenticationService authenticationService,
            AuditService auditService,
            CloudwatchMetricsService cloudwatchMetricsService,
            AuthSessionService authSessionService) {
        super(
                AuthCodeRequest.class,
                configurationService,
                sessionService,
                clientService,
                authenticationService,
                authSessionService);
        this.dynamoAuthCodeService = dynamoAuthCodeService;
        this.auditService = auditService;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
    }

    public AuthenticationAuthCodeHandler(ConfigurationService configurationService) {
        super(AuthCodeRequest.class, configurationService);
        this.dynamoAuthCodeService = new DynamoAuthCodeService(configurationService);
        this.auditService = new AuditService(configurationService);
        this.cloudwatchMetricsService = new CloudwatchMetricsService();
    }

    public AuthenticationAuthCodeHandler(
            ConfigurationService configurationService, RedisConnectionService redis) {
        super(AuthCodeRequest.class, configurationService, redis);
        this.dynamoAuthCodeService = new DynamoAuthCodeService(configurationService);
        this.auditService = new AuditService(configurationService);
        this.cloudwatchMetricsService = new CloudwatchMetricsService();
    }

    public AuthenticationAuthCodeHandler() {
        this(ConfigurationService.getInstance());
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
            AuthCodeRequest authCodeRequest,
            UserContext userContext) {
        attachLogFieldToLogs(AWS_REQUEST_ID, context.getAwsRequestId());
        try {
            var userProfile = userContext.getUserProfile();
            if (userProfile.isEmpty()) {
                LOG.info(
                        "Error message: Email from session does not have a user profile required to extract Subject ID");
                return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1049);
            }

            var authorisationCode = new AuthorizationCode();
            dynamoAuthCodeService.saveAuthCode(
                    userProfile.get().getSubjectID(),
                    authorisationCode.getValue(),
                    authCodeRequest.claims(),
                    false,
                    authCodeRequest.sectorIdentifier(),
                    authCodeRequest.isNewAccount(),
                    authCodeRequest.passwordResetTime(),
                    userContext.getClientSessionId());

            var state = State.parse(authCodeRequest.state());
            var redirectUri = URI.create(authCodeRequest.redirectUri());
            var authorizationResponse =
                    new AuthorizationSuccessResponse(
                            redirectUri, authorisationCode, null, state, null);

            if (configurationService.supportReauthSignoutEnabled()
                    && Boolean.TRUE.equals(authCodeRequest.isReauthJourney())) {
                var auditContext =
                        AuditContext.auditContextFromUserContext(
                                userContext,
                                userProfile.get().getSubjectID(),
                                userProfile.get().getEmail(),
                                IpAddressHelper.extractIpAddress(input),
                                userProfile.get().getPhoneNumber(),
                                PersistentIdHelper.extractPersistentIdFromHeaders(
                                        input.getHeaders()));

                var client = userContext.getClient().orElseThrow();
                var rpPairwiseId =
                        ClientSubjectHelper.getSubject(
                                        userProfile.get(),
                                        client,
                                        userContext.getAuthSession(),
                                        authenticationService,
                                        configurationService.getInternalSectorUri())
                                .getValue();
                var metadataBuilder = ReauthMetadataBuilder.builder(rpPairwiseId);

                if (userContext.getAuthSession().getPreservedReauthCountsForAuditMap() != null) {
                    metadataBuilder.withAllIncorrectAttemptCounts(
                            userContext.getAuthSession().getPreservedReauthCountsForAuditMap());
                } else {
                    LOG.warn("No preserved reauth counts found for reauth journey");
                }
                auditService.submitAuditEvent(
                        AUTH_REAUTH_SUCCESS, auditContext, metadataBuilder.build());
                cloudwatchMetricsService.incrementCounter(
                        CloudwatchMetrics.REAUTH_SUCCESS.getValue(),
                        Map.of(ENVIRONMENT.getValue(), configurationService.getEnvironment()));
                LOG.info("reauthentication successful");
                authSessionService.updateSession(
                        userContext.getAuthSession().withPreservedReauthCountsForAuditMap(null));
            }

            return generateApiGatewayProxyResponse(
                    200, new AuthCodeResponse(authorizationResponse.toURI().toString()));
        } catch (JsonException ex) {
            LOG.warn("Exception generating authcode. Returning 1001: ", ex);
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        }
    }
}

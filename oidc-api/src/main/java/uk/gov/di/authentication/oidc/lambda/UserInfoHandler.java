package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.openid.connect.sdk.UserInfoErrorResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.authentication.app.services.DynamoDocAppCriService;
import uk.gov.di.authentication.oidc.domain.OidcAuditableEvent;
import uk.gov.di.authentication.oidc.entity.AccessTokenInfo;
import uk.gov.di.authentication.oidc.services.AccessTokenService;
import uk.gov.di.authentication.oidc.services.UserInfoService;
import uk.gov.di.orchestration.audit.TxmaAuditUser;
import uk.gov.di.orchestration.shared.entity.ErrorResponse;
import uk.gov.di.orchestration.shared.entity.ValidClaims;
import uk.gov.di.orchestration.shared.exceptions.AccessTokenException;
import uk.gov.di.orchestration.shared.exceptions.ClientNotFoundException;
import uk.gov.di.orchestration.shared.services.AuditService;
import uk.gov.di.orchestration.shared.services.AuthenticationUserInfoStorageService;
import uk.gov.di.orchestration.shared.services.CloudwatchMetricsService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.DynamoClientService;
import uk.gov.di.orchestration.shared.services.DynamoIdentityService;
import uk.gov.di.orchestration.shared.services.JwksService;
import uk.gov.di.orchestration.shared.services.KmsConnectionService;
import uk.gov.di.orchestration.shared.services.OrchAccessTokenService;
import uk.gov.di.orchestration.shared.services.TokenValidationService;

import java.util.HashMap;
import java.util.Map;

import static com.nimbusds.oauth2.sdk.token.BearerTokenError.MISSING_TOKEN;
import static uk.gov.di.orchestration.shared.domain.CloudwatchMetricDimensions.CLIENT;
import static uk.gov.di.orchestration.shared.domain.CloudwatchMetricDimensions.ENVIRONMENT;
import static uk.gov.di.orchestration.shared.domain.CloudwatchMetrics.USER_INFO_RETURNED;
import static uk.gov.di.orchestration.shared.domain.RequestHeaders.AUTHORIZATION_HEADER;
import static uk.gov.di.orchestration.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.orchestration.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.AWS_REQUEST_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.CLIENT_SESSION_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.GOVUK_SIGNIN_JOURNEY_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachTraceId;
import static uk.gov.di.orchestration.shared.helpers.RequestHeaderHelper.getHeaderValueFromHeaders;
import static uk.gov.di.orchestration.shared.helpers.RequestHeaderHelper.headersContainValidHeader;
import static uk.gov.di.orchestration.shared.services.AuditService.MetadataPair.pair;

public class UserInfoHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(UserInfoHandler.class);
    private final ConfigurationService configurationService;
    private final UserInfoService userInfoService;
    private final AccessTokenService accessTokenService;
    private final AuditService auditService;
    private final CloudwatchMetricsService cloudwatchMetricsService;

    public UserInfoHandler(
            ConfigurationService configurationService,
            UserInfoService userInfoService,
            AccessTokenService accessTokenService,
            AuditService auditService,
            CloudwatchMetricsService cloudwatchMetricsService) {
        this.configurationService = configurationService;
        this.userInfoService = userInfoService;
        this.accessTokenService = accessTokenService;
        this.auditService = auditService;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
    }

    public UserInfoHandler() {
        this(ConfigurationService.getInstance());
    }

    public UserInfoHandler(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.userInfoService =
                new UserInfoService(
                        new DynamoIdentityService(configurationService),
                        new DynamoClientService(configurationService),
                        new DynamoDocAppCriService(configurationService),
                        new CloudwatchMetricsService(),
                        configurationService,
                        new AuthenticationUserInfoStorageService(configurationService));
        this.accessTokenService =
                new AccessTokenService(
                        new DynamoClientService(configurationService),
                        new TokenValidationService(
                                new JwksService(
                                        configurationService,
                                        new KmsConnectionService(configurationService)),
                                configurationService),
                        new OrchAccessTokenService(configurationService));
        this.auditService = new AuditService(configurationService);
        this.cloudwatchMetricsService = new CloudwatchMetricsService(configurationService);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        ThreadContext.clearMap();
        attachTraceId();
        attachLogFieldToLogs(AWS_REQUEST_ID, context.getAwsRequestId());
        return userInfoRequestHandler(input, context);
    }

    public APIGatewayProxyResponseEvent userInfoRequestHandler(
            APIGatewayProxyRequestEvent input, Context context) {
        LOG.info("Request received to the UserInfoHandler");
        if (!headersContainValidHeader(
                input.getHeaders(),
                AUTHORIZATION_HEADER,
                configurationService.getHeadersCaseInsensitive())) {
            LOG.warn("AccessToken is missing from request");
            return generateApiGatewayProxyResponse(
                    401,
                    "",
                    new UserInfoErrorResponse(MISSING_TOKEN).toHTTPResponse().getHeaderMap());
        }
        UserInfo userInfo;
        AccessTokenInfo accessTokenInfo;
        try {
            accessTokenInfo =
                    accessTokenService.parse(
                            getHeaderValueFromHeaders(
                                    input.getHeaders(),
                                    AUTHORIZATION_HEADER,
                                    configurationService.getHeadersCaseInsensitive()),
                            configurationService.isIdentityEnabled());
            userInfo = userInfoService.populateUserInfo(accessTokenInfo);
        } catch (AccessTokenException e) {
            LOG.warn(
                    "AccessTokenException: {}. Sending back UserInfoErrorResponse", e.getMessage());
            return generateApiGatewayProxyResponse(
                    401,
                    "",
                    new UserInfoErrorResponse(e.getError()).toHTTPResponse().getHeaderMap());
        } catch (ClientNotFoundException e) {
            LOG.warn("Client not found");
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1015);
        }
        String journeyId = accessTokenInfo.journeyId();
        attachLogFieldToLogs(CLIENT_SESSION_ID, journeyId);
        attachLogFieldToLogs(GOVUK_SIGNIN_JOURNEY_ID, journeyId);
        var subjectForAudit = userInfoService.calculateSubjectForAudit(accessTokenInfo);

        LOG.info("Successfully processed UserInfo request. Sending back UserInfo response");

        var returnCodeClaim = userInfo.getClaim(ValidClaims.RETURN_CODE.getValue());
        var metadataPairs = new AuditService.MetadataPair[] {};

        if (returnCodeClaim != null) {
            metadataPairs = new AuditService.MetadataPair[] {pair("return-code", returnCodeClaim)};
        }

        auditService.submitAuditEvent(
                OidcAuditableEvent.USER_INFO_RETURNED,
                accessTokenInfo.clientID(),
                TxmaAuditUser.user()
                        .withUserId(subjectForAudit)
                        .withGovukSigninJourneyId(journeyId),
                metadataPairs);

        var dimensions =
                new HashMap<>(
                        Map.of(
                                ENVIRONMENT.getValue(), configurationService.getEnvironment(),
                                CLIENT.getValue(), accessTokenInfo.clientID()));
        cloudwatchMetricsService.incrementCounter(USER_INFO_RETURNED.getValue(), dimensions);

        return generateApiGatewayProxyResponse(200, userInfo.toJSONString());
    }
}

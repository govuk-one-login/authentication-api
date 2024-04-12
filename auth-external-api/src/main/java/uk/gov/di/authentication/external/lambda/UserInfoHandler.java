package uk.gov.di.authentication.external.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import com.nimbusds.openid.connect.sdk.UserInfoErrorResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.authentication.external.domain.AuthExternalApiAuditableEvent;
import uk.gov.di.authentication.external.services.UserInfoService;
import uk.gov.di.authentication.shared.entity.token.AccessTokenStore;
import uk.gov.di.authentication.shared.exceptions.AccessTokenException;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.services.AccessTokenService;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;

import java.util.Objects;
import java.util.Optional;

import static uk.gov.di.authentication.shared.domain.RequestHeaders.AUTHORIZATION_HEADER;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.authentication.shared.helpers.RequestHeaderHelper.getHeaderValueFromHeaders;
import static uk.gov.di.authentication.shared.helpers.RequestHeaderHelper.headersContainValidHeader;

public class UserInfoHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(UserInfoHandler.class);
    private final ConfigurationService configurationService;
    private final UserInfoService userInfoService;
    private final AccessTokenService accessTokenService;
    private final AuditService auditService;

    public UserInfoHandler(
            ConfigurationService configurationService,
            UserInfoService userInfoService,
            AccessTokenService accessTokenService,
            AuditService auditService) {
        this.configurationService = configurationService;
        this.userInfoService = userInfoService;
        this.accessTokenService = accessTokenService;
        this.auditService = auditService;
    }

    public UserInfoHandler() {
        this(ConfigurationService.getInstance());
    }

    public UserInfoHandler(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.userInfoService =
                new UserInfoService(new DynamoService(configurationService), configurationService);
        this.accessTokenService = new AccessTokenService(configurationService, true);
        this.auditService = new AuditService(configurationService);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        try {
            return segmentedFunctionCall(
                    "auth-external-api::" + getClass().getSimpleName(),
                    () -> userInfoRequestHandler(input));
        } catch (Exception e) {
            LOG.error("Unexpected exception: {}", e.getMessage());
            return generateApiGatewayProxyResponse(500, "server_error");
        }
    }

    public APIGatewayProxyResponseEvent userInfoRequestHandler(APIGatewayProxyRequestEvent input) {
        ThreadContext.clearMap();
        LOG.info("Request received to the UserInfoHandler");
        if (!headersContainValidHeader(
                input.getHeaders(),
                AUTHORIZATION_HEADER,
                configurationService.getHeadersCaseInsensitive())) {
            LOG.warn("AccessToken is missing from request");
            return generateApiGatewayProxyResponse(
                    401,
                    "",
                    new UserInfoErrorResponse(BearerTokenError.MISSING_TOKEN)
                            .toHTTPResponse()
                            .getHeaderMap());
        }
        UserInfo userInfo;
        AccessToken accessToken;
        AccessTokenStore accessTokenStore;
        try {
            String authorizationHeader =
                    getHeaderValueFromHeaders(
                            input.getHeaders(),
                            AUTHORIZATION_HEADER,
                            configurationService.getHeadersCaseInsensitive());
            accessToken =
                    accessTokenService.getAccessTokenFromAuthorizationHeader(authorizationHeader);

            accessTokenStore =
                    accessTokenService
                            .getAccessTokenStore(accessToken.getValue())
                            .orElseThrow(
                                    () ->
                                            new AccessTokenException(
                                                    "Bearer token not found in database",
                                                    BearerTokenError.INVALID_TOKEN));

            if (!isAccessStoreValid(accessTokenStore)) {
                throw new AccessTokenException(
                        "Invalid bearer token", BearerTokenError.INVALID_TOKEN);
            }
            userInfo = userInfoService.populateUserInfo(accessTokenStore);
        } catch (AccessTokenException e) {
            LOG.warn(
                    "AccessTokenException: {}. Sending back UserInfoErrorResponse", e.getMessage());
            return generateApiGatewayProxyResponse(
                    401,
                    "",
                    new UserInfoErrorResponse(e.getError()).toHTTPResponse().getHeaderMap());
        }

        LOG.info(
                "Successfully processed UserInfo request. Setting token status to used and sending back UserInfo response");

        auditService.submitAuditEvent(
                AuthExternalApiAuditableEvent.USERINFO_SENT_TO_ORCHESTRATION,
                AuditService.UNKNOWN,
                AuditService.UNKNOWN,
                AuditService.UNKNOWN,
                Objects.isNull(userInfo.getSubject())
                        ? AuditService.UNKNOWN
                        : userInfo.getSubject().getValue(),
                Objects.isNull(userInfo.getEmailAddress())
                        ? AuditService.UNKNOWN
                        : userInfo.getEmailAddress(),
                AuditService.UNKNOWN,
                Objects.isNull(userInfo.getPhoneNumber())
                        ? AuditService.UNKNOWN
                        : userInfo.getPhoneNumber(),
                AuditService.UNKNOWN);

        Optional<AccessTokenStore> updatedTokenStore =
                accessTokenService.setAccessTokenStoreUsed(accessToken.getValue(), true);

        if (updatedTokenStore.isEmpty() || !updatedTokenStore.get().isUsed()) {
            LOG.error(
                    "Access token store was unexpectedly empty or was not set as used for the following token: {}",
                    accessToken.getValue());
        }

        return generateApiGatewayProxyResponse(200, userInfo.toJSONString());
    }

    private boolean isAccessStoreValid(AccessTokenStore accessTokenStore) {
        if (accessTokenStore.isUsed()) {
            LOG.warn("Access token already used");
            return false;
        }
        if (accessTokenStore.getTimeToExist() * 1000 < NowHelper.now().getTime()) {
            LOG.error(
                    "Access token expired - this should not have been returned from the database service");
            return false;
        }
        return true;
    }
}

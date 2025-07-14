package uk.gov.di.authentication.external.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.id.Identifier;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import com.nimbusds.openid.connect.sdk.UserInfoErrorResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.external.services.UserInfoService;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.token.AccessTokenStore;
import uk.gov.di.authentication.shared.exceptions.AccessTokenException;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.services.AccessTokenService;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.mfa.MFAMethodsService;

import java.util.Map;
import java.util.Optional;

import static uk.gov.di.authentication.external.domain.AuthExternalApiAuditableEvent.AUTH_USERINFO_SENT_TO_ORCHESTRATION;
import static uk.gov.di.authentication.shared.domain.RequestHeaders.AUTHORIZATION_HEADER;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachSessionIdToLogs;
import static uk.gov.di.authentication.shared.helpers.RequestHeaderHelper.getOptionalHeaderValueFromHeaders;

public class UserInfoHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(UserInfoHandler.class);
    private final ConfigurationService configurationService;
    private final UserInfoService userInfoService;
    private final AccessTokenService accessTokenService;
    private final AuditService auditService;
    private final AuthSessionService authSessionService;

    public UserInfoHandler(
            ConfigurationService configurationService,
            UserInfoService userInfoService,
            AccessTokenService accessTokenService,
            AuditService auditService,
            AuthSessionService authSessionService) {
        this.configurationService = configurationService;
        this.userInfoService = userInfoService;
        this.accessTokenService = accessTokenService;
        this.auditService = auditService;
        this.authSessionService = authSessionService;
    }

    public UserInfoHandler() {
        this(ConfigurationService.getInstance());
    }

    public UserInfoHandler(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.userInfoService =
                new UserInfoService(
                        new DynamoService(configurationService),
                        new MFAMethodsService(configurationService),
                        configurationService);
        this.accessTokenService =
                new AccessTokenService(
                        configurationService, new CloudwatchMetricsService(configurationService));
        this.auditService = new AuditService(configurationService);
        this.authSessionService = new AuthSessionService(configurationService);
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
        Map<String, String> headers = input.getHeaders();

        Optional<String> authorisationHeader =
                getOptionalHeaderValueFromHeaders(
                        headers,
                        AUTHORIZATION_HEADER,
                        configurationService.getHeadersCaseInsensitive());

        if (authorisationHeader.isEmpty()) {
            LOG.warn("AccessToken is missing from request");
            return generateApiGatewayProxyResponse(
                    401,
                    "",
                    new UserInfoErrorResponse(BearerTokenError.MISSING_TOKEN)
                            .toHTTPResponse()
                            .getHeaderMap());
        }

        AuthSessionItem authSession;

        Optional<AuthSessionItem> optionalAuthSession =
                authSessionService.getSessionFromRequestHeaders(input.getHeaders());

        if (optionalAuthSession.isEmpty()) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.SESSION_ID_MISSING);
        }
        authSession = optionalAuthSession.get();

        attachSessionIdToLogs(authSession.getSessionId());

        UserInfo userInfo;
        AccessToken accessToken;
        AccessTokenStore accessTokenStore;
        try {

            accessToken =
                    accessTokenService.getAccessTokenFromAuthorizationHeader(
                            authorisationHeader.get());

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
            logNewAccountValues(accessTokenStore, authSession);
            userInfo = userInfoService.populateUserInfo(accessTokenStore, authSession);
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

        var subjectId =
                Optional.ofNullable(userInfo.getSubject())
                        .map(Identifier::getValue)
                        .orElse(AuditService.UNKNOWN);
        var email = Optional.ofNullable(userInfo.getEmailAddress()).orElse(AuditService.UNKNOWN);
        var phoneNumber =
                Optional.ofNullable(userInfo.getPhoneNumber()).orElse(AuditService.UNKNOWN);
        var auditContext =
                AuditContext.emptyAuditContext()
                        .withSubjectId(subjectId)
                        .withEmail(email)
                        .withPhoneNumber(phoneNumber);

        auditService.submitAuditEvent(AUTH_USERINFO_SENT_TO_ORCHESTRATION, auditContext);

        Optional<AccessTokenStore> updatedTokenStore =
                accessTokenService.setAccessTokenStoreUsed(accessToken.getValue(), true);

        if (updatedTokenStore.isEmpty() || !updatedTokenStore.get().isUsed()) {
            LOG.error(
                    "Access token store was unexpectedly empty or was not set as used for the following token: {}",
                    accessToken.getValue());
        }

        authSessionService.updateSession(
                authSession.withAccountState(AuthSessionItem.AccountState.EXISTING));
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

    private void logNewAccountValues(
            AccessTokenStore accessTokenStore, AuthSessionItem authSession) {
        try {
            LOG.info("Value from session: {}", authSession.getIsNewAccount());
            LOG.info("Value from token: {}", accessTokenStore.getIsNewAccount());

        } catch (Exception e) {
            LOG.warn("Unexpected error when: {}", e.getMessage());
        }
    }
}

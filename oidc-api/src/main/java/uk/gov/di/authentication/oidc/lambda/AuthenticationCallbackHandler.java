package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.ipv.services.IPVAuthorisationService;
import uk.gov.di.authentication.oidc.domain.OidcAuditableEvent;
import uk.gov.di.authentication.oidc.domain.OrchestrationAuditableEvent;
import uk.gov.di.authentication.oidc.exceptions.AuthenticationCallbackException;
import uk.gov.di.authentication.oidc.services.AuthenticationAuthorizationService;
import uk.gov.di.authentication.oidc.services.AuthenticationTokenService;
import uk.gov.di.authentication.oidc.services.InitiateIPVAuthorisationService;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.ResponseHeaders;
import uk.gov.di.orchestration.shared.entity.Session;
import uk.gov.di.orchestration.shared.entity.VectorOfTrust;
import uk.gov.di.orchestration.shared.exceptions.UnsuccessfulCredentialResponseException;
import uk.gov.di.orchestration.shared.helpers.ConstructUriHelper;
import uk.gov.di.orchestration.shared.helpers.CookieHelper;
import uk.gov.di.orchestration.shared.helpers.IpAddressHelper;
import uk.gov.di.orchestration.shared.helpers.PersistentIdHelper;
import uk.gov.di.orchestration.shared.services.*;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import static com.nimbusds.oauth2.sdk.http.HTTPRequest.Method.GET;
import static java.net.http.HttpClient.newHttpClient;
import static java.util.Objects.isNull;
import static java.util.Objects.nonNull;
import static uk.gov.di.orchestration.shared.conditions.IdentityHelper.identityRequired;
import static uk.gov.di.orchestration.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.orchestration.shared.helpers.ConstructUriHelper.buildURI;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.CLIENT_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.CLIENT_SESSION_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.GOVUK_SIGNIN_JOURNEY_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.PERSISTENT_SESSION_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachSessionIdToLogs;
import static uk.gov.di.orchestration.shared.services.AuditService.MetadataPair.pair;

public class AuthenticationCallbackHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(AuthenticationCallbackHandler.class);
    private final ConfigurationService configurationService;
    private final AuthenticationAuthorizationService authorisationService;
    private final AuthenticationTokenService tokenService;
    private final SessionService sessionService;
    private final ClientSessionService clientSessionService;
    private final AuditService auditService;
    private final AuthenticationUserInfoStorageService userInfoStorageService;
    private final CloudwatchMetricsService cloudwatchMetricsService;
    private final AuthorisationCodeService authorisationCodeService;
    private final ClientService clientService;
    private final InitiateIPVAuthorisationService initiateIPVAuthorisationService;
    private final AccountInterventionService accountInterventionService;
    private final CookieHelper cookieHelper;
    private static final String ERROR_PAGE_REDIRECT_PATH = "error";

    public AuthenticationCallbackHandler() {
        this(ConfigurationService.getInstance());
    }

    public AuthenticationCallbackHandler(ConfigurationService configurationService) {

        var kmsConnectionService = new KmsConnectionService(configurationService);
        var redisConnectionService = new RedisConnectionService(configurationService);
        this.configurationService = configurationService;
        this.authorisationService = new AuthenticationAuthorizationService(redisConnectionService);
        this.tokenService =
                new AuthenticationTokenService(configurationService, kmsConnectionService);
        this.sessionService = new SessionService(configurationService);
        this.clientSessionService = new ClientSessionService(configurationService);
        this.auditService = new AuditService(configurationService);
        this.userInfoStorageService =
                new AuthenticationUserInfoStorageService(configurationService);
        this.cookieHelper = new CookieHelper();
        this.cloudwatchMetricsService = new CloudwatchMetricsService(configurationService);
        this.authorisationCodeService = new AuthorisationCodeService(configurationService);
        this.clientService = new DynamoClientService(configurationService);
        this.initiateIPVAuthorisationService =
                new InitiateIPVAuthorisationService(
                        configurationService,
                        auditService,
                        new IPVAuthorisationService(
                                configurationService, redisConnectionService, kmsConnectionService),
                        cloudwatchMetricsService);
        this.accountInterventionService =
                new AccountInterventionService(
                        configurationService, newHttpClient(), cloudwatchMetricsService);
    }

    public AuthenticationCallbackHandler(
            ConfigurationService configurationService,
            AuthenticationAuthorizationService responseService,
            AuthenticationTokenService tokenService,
            SessionService sessionService,
            ClientSessionService clientSessionService,
            AuditService auditService,
            AuthenticationUserInfoStorageService dynamoAuthUserInfoService,
            CookieHelper cookieHelper,
            CloudwatchMetricsService cloudwatchMetricsService,
            AuthorisationCodeService authorisationCodeService,
            ClientService clientService,
            InitiateIPVAuthorisationService initiateIPVAuthorisationService,
            AccountInterventionService accountInterventionService) {
        this.configurationService = configurationService;
        this.authorisationService = responseService;
        this.tokenService = tokenService;
        this.sessionService = sessionService;
        this.clientSessionService = clientSessionService;
        this.auditService = auditService;
        this.userInfoStorageService = dynamoAuthUserInfoService;
        this.cookieHelper = cookieHelper;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
        this.authorisationCodeService = authorisationCodeService;
        this.clientService = clientService;
        this.initiateIPVAuthorisationService = initiateIPVAuthorisationService;
        this.accountInterventionService = accountInterventionService;
    }

    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        LOG.info("Request received to AuthenticationCallbackHandler");
        try {
            CookieHelper.SessionCookieIds sessionCookiesIds =
                    cookieHelper.parseSessionCookie(input.getHeaders()).orElse(null);

            if (sessionCookiesIds == null) {
                throw new AuthenticationCallbackException("No session cookie found");
            }

            Session userSession =
                    sessionService
                            .readSessionFromRedis(sessionCookiesIds.getSessionId())
                            .orElseThrow(
                                    () ->
                                            new AuthenticationCallbackException(
                                                    "Orchestration user session not found"));

            attachSessionIdToLogs(userSession);
            var clientSessionId = sessionCookiesIds.getClientSessionId();
            attachLogFieldToLogs(CLIENT_SESSION_ID, clientSessionId);
            attachLogFieldToLogs(GOVUK_SIGNIN_JOURNEY_ID, clientSessionId);

            var clientSession =
                    clientSessionService
                            .getClientSession(clientSessionId)
                            .orElseThrow(
                                    () ->
                                            new AuthenticationCallbackException(
                                                    "ClientSession not found"));

            String persistentSessionId =
                    PersistentIdHelper.extractPersistentIdFromCookieHeader(input.getHeaders());
            attachLogFieldToLogs(PERSISTENT_SESSION_ID, persistentSessionId);

            var authenticationRequest =
                    AuthenticationRequest.parse(clientSession.getAuthRequestParams());

            String clientId = authenticationRequest.getClientID().getValue();
            attachLogFieldToLogs(CLIENT_ID, clientId);

            boolean requestValid =
                    authorisationService.validateRequest(
                            input.getQueryStringParameters(), userSession.getSessionId());

            if (!requestValid) {
                return generateAuthenticationErrorResponse(
                        authenticationRequest,
                        OAuth2Error.SERVER_ERROR,
                        clientSessionId,
                        userSession.getSessionId(),
                        persistentSessionId);
            }

            auditService.submitAuditEvent(
                    OrchestrationAuditableEvent.AUTH_CALLBACK_RESPONSE_RECEIVED,
                    clientSessionId,
                    userSession.getSessionId(),
                    clientId,
                    AuditService.UNKNOWN,
                    AuditService.UNKNOWN,
                    AuditService.UNKNOWN,
                    AuditService.UNKNOWN,
                    persistentSessionId);

            var tokenRequest =
                    tokenService.constructTokenRequest(
                            input.getQueryStringParameters().get("code"));
            TokenResponse tokenResponse = tokenService.sendTokenRequest(tokenRequest);
            if (tokenResponse.indicatesSuccess()) {
                LOG.info("TokenResponse was successful");
                auditService.submitAuditEvent(
                        OrchestrationAuditableEvent.AUTH_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED,
                        clientSessionId,
                        userSession.getSessionId(),
                        clientId,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        persistentSessionId);
            } else {
                LOG.error(
                        "Authentication TokenResponse was not successful: {}",
                        tokenResponse.toErrorResponse().toJSONObject());
                auditService.submitAuditEvent(
                        OrchestrationAuditableEvent.AUTH_UNSUCCESSFUL_TOKEN_RESPONSE_RECEIVED,
                        clientSessionId,
                        userSession.getSessionId(),
                        clientId,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        persistentSessionId);
                return redirectToFrontendErrorPage();
            }

            try {
                URI userInfoURI =
                        buildURI(
                                configurationService.getAuthenticationBackendURI().toString(),
                                "userinfo");

                HTTPRequest authorizationRequest = new HTTPRequest(GET, userInfoURI);
                authorizationRequest.setAuthorization(
                        tokenResponse
                                .toSuccessResponse()
                                .getTokens()
                                .getAccessToken()
                                .toAuthorizationHeader());

                UserInfo userInfo = tokenService.sendUserInfoDataRequest(authorizationRequest);

                auditService.submitAuditEvent(
                        OrchestrationAuditableEvent.AUTH_SUCCESSFUL_USERINFO_RESPONSE_RECEIVED,
                        clientSessionId,
                        userSession.getSessionId(),
                        clientId,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        persistentSessionId);
                LOG.info("Adding Authentication userinfo to dynamo");
                userInfoStorageService.addAuthenticationUserInfoData(
                        userInfo.getSubject().getValue(), userInfo);

                ClientRegistry client = clientService.getClient(clientId).orElseThrow();

                boolean identityRequired =
                        identityRequired(
                                clientSession.getAuthRequestParams(),
                                client.isIdentityVerificationSupported(),
                                configurationService.isIdentityEnabled());

                boolean isTestJourney = false;
                if (nonNull(userInfo.getEmailAddress())) {
                    isTestJourney =
                            clientService.isTestJourney(clientId, userInfo.getEmailAddress());
                }

                Map<String, String> dimensions =
                        new HashMap<>(
                                Map.of(
                                        "IsNewAccount",
                                        userInfo.getClaim("new_account").toString(),
                                        "Environment",
                                        configurationService.getEnvironment(),
                                        "Client",
                                        clientId,
                                        "IsTest",
                                        Boolean.toString(isTestJourney),
                                        "ClientName",
                                        clientSession.getClientName()));

                if (Objects.nonNull(userSession.getVerifiedMfaMethodType())) {
                    dimensions.put("MfaMethod", userSession.getVerifiedMfaMethodType().getValue());
                } else {
                    LOG.info(
                            "No mfa method to set. User is either authenticated or signing in from a low level service");
                }

                cloudwatchMetricsService.incrementCounter("AuthenticationCallback", dimensions);

                var accountStatus =
                        accountInterventionService.getAccountStatus(
                                userInfo.getSubject().getValue());

                Boolean reproveIdentity =
                        configurationService.isAccountInterventionServiceActionEnabled()
                                ? accountStatus.reproveIdentity()
                                : null;

                if (identityRequired) {
                    return initiateIPVAuthorisationService.sendRequestToIPV(
                            input,
                            authenticationRequest,
                            userInfo,
                            userSession,
                            client,
                            clientId,
                            clientSessionId,
                            persistentSessionId,
                            reproveIdentity);
                }

                URI clientRedirectURI = authenticationRequest.getRedirectionURI();
                State state = authenticationRequest.getState();
                ResponseMode responseMode = authenticationRequest.getResponseMode();

                LOG.info("Redirecting to: {} with state: {}", clientRedirectURI, state);

                VectorOfTrust requestedVectorOfTrust = clientSession.getEffectiveVectorOfTrust();
                if (isNull(userSession.getCurrentCredentialStrength())
                        || requestedVectorOfTrust
                                        .getCredentialTrustLevel()
                                        .compareTo(userSession.getCurrentCredentialStrength())
                                > 0) {
                    userSession.setCurrentCredentialStrength(
                            requestedVectorOfTrust.getCredentialTrustLevel());
                }

                var authCode =
                        authorisationCodeService.generateAndSaveAuthorisationCode(
                                clientSessionId, userSession.getEmailAddress(), clientSession);

                var authenticationResponse =
                        new AuthenticationSuccessResponse(
                                clientRedirectURI, authCode, null, null, state, null, responseMode);

                LOG.info("Successfully processed request");

                auditService.submitAuditEvent(
                        OidcAuditableEvent.AUTH_CODE_ISSUED,
                        clientSessionId,
                        userSession.getSessionId(),
                        clientId,
                        userInfo.getSubject().getValue(),
                        Objects.isNull(userSession.getEmailAddress())
                                ? AuditService.UNKNOWN
                                : userSession.getEmailAddress(),
                        IpAddressHelper.extractIpAddress(input),
                        Objects.isNull(userInfo.getPhoneNumber())
                                ? AuditService.UNKNOWN
                                : userInfo.getPhoneNumber(),
                        persistentSessionId,
                        pair("internalSubjectId", AuditService.UNKNOWN),
                        pair("isNewAccount", userInfo.getClaim("new_account")),
                        pair("rpPairwiseId", userInfo.getClaim("rp_client_id")),
                        pair("nonce", authenticationRequest.getNonce()),
                        pair("authCode", authCode.getValue()));

                return generateApiGatewayProxyResponse(
                        302,
                        "",
                        Map.of(ResponseHeaders.LOCATION, authenticationResponse.toURI().toString()),
                        null);

            } catch (UnsuccessfulCredentialResponseException e) {
                auditService.submitAuditEvent(
                        OrchestrationAuditableEvent.AUTH_UNSUCCESSFUL_USERINFO_RESPONSE_RECEIVED,
                        clientSessionId,
                        userSession.getSessionId(),
                        clientId,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        persistentSessionId);
                LOG.error(
                        "Orchestration to Authentication userinfo request was not successful: {}",
                        e.getMessage());
                return redirectToFrontendErrorPage();
            }
        } catch (AuthenticationCallbackException e) {
            LOG.warn(e.getMessage());
            return redirectToFrontendErrorPage();
        } catch (ParseException e) {
            LOG.info("Cannot retrieve auth request params from client session id");
            return redirectToFrontendErrorPage();
        }
    }

    private APIGatewayProxyResponseEvent generateAuthenticationErrorResponse(
            AuthenticationRequest authenticationRequest,
            ErrorObject errorObject,
            String clientSessionId,
            String sessionId,
            String persistentSessionId) {
        LOG.warn(
                "Error in Authentication Authorisation Response. ErrorCode: {}. ErrorDescription: {}",
                errorObject.getCode(),
                errorObject.getDescription());
        auditService.submitAuditEvent(
                OrchestrationAuditableEvent.AUTH_UNSUCCESSFUL_CALLBACK_RESPONSE_RECEIVED,
                clientSessionId,
                sessionId,
                authenticationRequest.getClientID().getValue(),
                AuditService.UNKNOWN,
                AuditService.UNKNOWN,
                AuditService.UNKNOWN,
                AuditService.UNKNOWN,
                persistentSessionId);
        var errorResponse =
                new AuthenticationErrorResponse(
                        authenticationRequest.getRedirectionURI(),
                        errorObject,
                        authenticationRequest.getState(),
                        authenticationRequest.getResponseMode());
        return generateApiGatewayProxyResponse(
                302, "", Map.of(ResponseHeaders.LOCATION, errorResponse.toURI().toString()), null);
    }

    private APIGatewayProxyResponseEvent redirectToFrontendErrorPage() {
        LOG.info("Redirecting to frontend error page");
        return generateApiGatewayProxyResponse(
                302,
                "",
                Map.of(
                        ResponseHeaders.LOCATION,
                        ConstructUriHelper.buildURI(
                                        configurationService.getLoginURI().toString(),
                                        ERROR_PAGE_REDIRECT_PATH)
                                .toString()),
                null);
    }
}

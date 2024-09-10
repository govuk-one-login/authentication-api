package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.claims.PersonClaims;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import org.bouncycastle.jcajce.provider.digest.SHA256;
import org.bouncycastle.util.encoders.Hex;
import org.jetbrains.annotations.NotNull;
import uk.gov.di.authentication.ipv.services.IPVAuthorisationService;
import uk.gov.di.authentication.oidc.domain.OidcAuditableEvent;
import uk.gov.di.authentication.oidc.domain.OrchestrationAuditableEvent;
import uk.gov.di.authentication.oidc.exceptions.AuthenticationCallbackException;
import uk.gov.di.authentication.oidc.exceptions.AuthenticationCallbackValidationException;
import uk.gov.di.authentication.oidc.services.AuthenticationAuthorizationService;
import uk.gov.di.authentication.oidc.services.AuthenticationTokenService;
import uk.gov.di.authentication.oidc.services.InitiateIPVAuthorisationService;
import uk.gov.di.orchestration.audit.AuditContext;
import uk.gov.di.orchestration.audit.TxmaAuditUser;
import uk.gov.di.orchestration.shared.api.AuthFrontend;
import uk.gov.di.orchestration.shared.api.OidcAPI;
import uk.gov.di.orchestration.shared.conditions.MfaHelper;
import uk.gov.di.orchestration.shared.entity.AccountIntervention;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.ClientSession;
import uk.gov.di.orchestration.shared.entity.CredentialTrustLevel;
import uk.gov.di.orchestration.shared.entity.LevelOfConfidence;
import uk.gov.di.orchestration.shared.entity.ResponseHeaders;
import uk.gov.di.orchestration.shared.entity.Session;
import uk.gov.di.orchestration.shared.entity.Session.AccountState;
import uk.gov.di.orchestration.shared.entity.VectorOfTrust;
import uk.gov.di.orchestration.shared.exceptions.UnsuccessfulCredentialResponseException;
import uk.gov.di.orchestration.shared.helpers.CookieHelper;
import uk.gov.di.orchestration.shared.helpers.IpAddressHelper;
import uk.gov.di.orchestration.shared.helpers.PersistentIdHelper;
import uk.gov.di.orchestration.shared.services.AccountInterventionService;
import uk.gov.di.orchestration.shared.services.AuditService;
import uk.gov.di.orchestration.shared.services.AuthenticationUserInfoStorageService;
import uk.gov.di.orchestration.shared.services.AuthorisationCodeService;
import uk.gov.di.orchestration.shared.services.ClientService;
import uk.gov.di.orchestration.shared.services.ClientSessionService;
import uk.gov.di.orchestration.shared.services.CloudwatchMetricsService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.DynamoClientService;
import uk.gov.di.orchestration.shared.services.KmsConnectionService;
import uk.gov.di.orchestration.shared.services.LogoutService;
import uk.gov.di.orchestration.shared.services.NoSessionOrchestrationService;
import uk.gov.di.orchestration.shared.services.RedirectService;
import uk.gov.di.orchestration.shared.services.RedisConnectionService;
import uk.gov.di.orchestration.shared.services.SerializationService;
import uk.gov.di.orchestration.shared.services.SessionService;
import uk.gov.di.orchestration.shared.services.TokenService;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import static com.nimbusds.oauth2.sdk.http.HTTPRequest.Method.GET;
import static java.lang.String.format;
import static java.util.Objects.isNull;
import static java.util.Objects.nonNull;
import static uk.gov.di.authentication.oidc.domain.OrchestrationAuditableEvent.AUTH_UNSUCCESSFUL_USERINFO_RESPONSE_RECEIVED;
import static uk.gov.di.orchestration.shared.conditions.DocAppUserHelper.isDocCheckingAppUserWithSubjectId;
import static uk.gov.di.orchestration.shared.conditions.IdentityHelper.identityRequired;
import static uk.gov.di.orchestration.shared.domain.RequestHeaders.SESSION_ID_HEADER;
import static uk.gov.di.orchestration.shared.entity.Session.AccountState.EXISTING;
import static uk.gov.di.orchestration.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.orchestration.shared.helpers.AuditHelper.attachTxmaAuditFieldFromHeaders;
import static uk.gov.di.orchestration.shared.helpers.ConstructUriHelper.buildURI;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.CLIENT_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.CLIENT_SESSION_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.GOVUK_SIGNIN_JOURNEY_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.PERSISTENT_SESSION_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachSessionIdToLogs;
import static uk.gov.di.orchestration.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.orchestration.shared.services.AuditService.UNKNOWN;

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
    private final LogoutService logoutService;
    private final AuthFrontend authFrontend;

    public AuthenticationCallbackHandler() {
        this(ConfigurationService.getInstance());
    }

    public AuthenticationCallbackHandler(ConfigurationService configurationService) {
        var kmsConnectionService = new KmsConnectionService(configurationService);
        var redisConnectionService = new RedisConnectionService(configurationService);
        var oidcApi = new OidcAPI(configurationService);
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
                        cloudwatchMetricsService,
                        new NoSessionOrchestrationService(configurationService),
                        new TokenService(
                                configurationService,
                                redisConnectionService,
                                kmsConnectionService,
                                oidcApi));
        this.accountInterventionService =
                new AccountInterventionService(
                        configurationService, cloudwatchMetricsService, auditService);
        this.logoutService = new LogoutService(configurationService);
        this.authFrontend = new AuthFrontend(configurationService);
    }

    public AuthenticationCallbackHandler(
            ConfigurationService configurationService, RedisConnectionService redis) {

        var kmsConnectionService = new KmsConnectionService(configurationService);
        var redisConnectionService = redis;
        this.configurationService = configurationService;
        this.authorisationService = new AuthenticationAuthorizationService(redisConnectionService);
        this.tokenService =
                new AuthenticationTokenService(configurationService, kmsConnectionService);
        this.sessionService = new SessionService(configurationService, redisConnectionService);
        this.clientSessionService =
                new ClientSessionService(configurationService, redisConnectionService);
        this.auditService = new AuditService(configurationService);
        this.userInfoStorageService =
                new AuthenticationUserInfoStorageService(configurationService);
        this.cookieHelper = new CookieHelper();
        this.cloudwatchMetricsService = new CloudwatchMetricsService(configurationService);
        this.authorisationCodeService =
                new AuthorisationCodeService(
                        configurationService,
                        redisConnectionService,
                        SerializationService.getInstance());
        this.clientService = new DynamoClientService(configurationService);
        this.initiateIPVAuthorisationService =
                new InitiateIPVAuthorisationService(
                        configurationService,
                        auditService,
                        new IPVAuthorisationService(
                                configurationService, redisConnectionService, kmsConnectionService),
                        cloudwatchMetricsService,
                        new NoSessionOrchestrationService(
                                configurationService, redisConnectionService),
                        new TokenService(
                                configurationService,
                                redisConnectionService,
                                kmsConnectionService,
                                new OidcAPI(configurationService)));
        this.accountInterventionService =
                new AccountInterventionService(
                        configurationService, cloudwatchMetricsService, auditService);
        this.logoutService = new LogoutService(configurationService, redisConnectionService);
        this.authFrontend = new AuthFrontend(configurationService);
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
            AccountInterventionService accountInterventionService,
            LogoutService logoutService,
            AuthFrontend authFrontend) {
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
        this.logoutService = logoutService;
        this.authFrontend = authFrontend;
    }

    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        ThreadContext.clearMap();
        LOG.info("Request received to AuthenticationCallbackHandler");
        attachTxmaAuditFieldFromHeaders(input.getHeaders());

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

            var user =
                    TxmaAuditUser.user()
                            .withGovukSigninJourneyId(clientSessionId)
                            .withSessionId(userSession.getSessionId())
                            .withPersistentSessionId(persistentSessionId);

            var authenticationRequest =
                    AuthenticationRequest.parse(clientSession.getAuthRequestParams());

            String clientId = authenticationRequest.getClientID().getValue();
            attachLogFieldToLogs(CLIENT_ID, clientId);

            var validationFailureResponse =
                    generateAuthenticationErrorResponseIfRequestInvalid(
                            authenticationRequest, input, user, userSession);
            if (validationFailureResponse.isPresent()) {
                return validationFailureResponse.get();
            }

            auditService.submitAuditEvent(
                    OrchestrationAuditableEvent.AUTH_CALLBACK_RESPONSE_RECEIVED, clientId, user);

            var tokenRequest =
                    tokenService.constructTokenRequest(
                            input.getQueryStringParameters().get("code"));
            TokenResponse tokenResponse = tokenService.sendTokenRequest(tokenRequest);
            if (tokenResponse.indicatesSuccess()) {
                LOG.info("TokenResponse was successful");
                auditService.submitAuditEvent(
                        OrchestrationAuditableEvent.AUTH_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED,
                        clientId,
                        user);
            } else {
                LOG.error(
                        "Authentication TokenResponse was not successful: {}",
                        tokenResponse.toErrorResponse().toJSONObject());
                auditService.submitAuditEvent(
                        OrchestrationAuditableEvent.AUTH_UNSUCCESSFUL_TOKEN_RESPONSE_RECEIVED,
                        clientId,
                        user);
                return RedirectService.redirectToFrontendErrorPage(authFrontend.errorURI());
            }

            try {
                URI userInfoURI =
                        buildURI(
                                configurationService.getAuthenticationBackendURI().toString(),
                                "userinfo");
                var sessionId = userSession.getSessionId();
                HTTPRequest authorizationRequest = new HTTPRequest(GET, userInfoURI);
                authorizationRequest.setHeader(SESSION_ID_HEADER, sessionId);
                authorizationRequest.setAuthorization(
                        tokenResponse
                                .toSuccessResponse()
                                .getTokens()
                                .getAccessToken()
                                .toAuthorizationHeader());
                UserInfo userInfo = tokenService.sendUserInfoDataRequest(authorizationRequest);

                auditService.submitAuditEvent(
                        OrchestrationAuditableEvent.AUTH_SUCCESSFUL_USERINFO_RESPONSE_RECEIVED,
                        clientId,
                        user);
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

                Boolean newAccount = userInfo.getBooleanClaim("new_account");
                AccountState accountState = newAccount ? AccountState.NEW : AccountState.EXISTING;
                var docAppJourney = isDocCheckingAppUserWithSubjectId(clientSession);
                Map<String, String> dimensions =
                        buildDimensions(
                                accountState,
                                clientId,
                                isTestJourney,
                                docAppJourney,
                                clientSession,
                                userSession);

                user =
                        user.withUserId(userInfo.getSubject().getValue())
                                .withEmail(
                                        Optional.of(userSession)
                                                .map(Session::getEmailAddress)
                                                .orElse(UNKNOWN))
                                .withPhone(
                                        Optional.of(userInfo)
                                                .map(PersonClaims::getPhoneNumber)
                                                .orElse(UNKNOWN))
                                .withIpAddress(IpAddressHelper.extractIpAddress(input));

                auditService.submitAuditEvent(
                        OidcAuditableEvent.AUTHENTICATION_COMPLETE,
                        clientId,
                        user,
                        pair("new_account", newAccount),
                        pair("test_user", isTestJourney));

                cloudwatchMetricsService.incrementCounter("AuthenticationCallback", dimensions);

                var auditContext =
                        new AuditContext(
                                clientSessionId,
                                userSession.getSessionId(),
                                clientId,
                                userInfo.getSubject().getValue(),
                                Objects.isNull(userSession.getEmailAddress())
                                        ? UNKNOWN
                                        : userSession.getEmailAddress(),
                                IpAddressHelper.extractIpAddress(input),
                                Objects.isNull(userInfo.getPhoneNumber())
                                        ? UNKNOWN
                                        : userInfo.getPhoneNumber(),
                                persistentSessionId);

                Long passwordResetTime = getPasswordResetTimeClaim(userInfo);
                AccountIntervention intervention =
                        accountInterventionService.getAccountIntervention(
                                userInfo.getSubject().getValue(), passwordResetTime, auditContext);

                Boolean reproveIdentity = null;
                if (configurationService.isAccountInterventionServiceActionEnabled()) {
                    reproveIdentity = intervention.getReproveIdentity();
                    switch (intervention.getStatus()) {
                        case BLOCKED,
                                SUSPENDED_RESET_PASSWORD,
                                SUSPENDED_RESET_PASSWORD_REPROVE_ID -> {
                            return logoutService.handleAccountInterventionLogout(
                                    userSession, input, clientId, intervention);
                        }
                        case SUSPENDED_NO_ACTION -> {
                            if (!identityRequired) {
                                return logoutService.handleAccountInterventionLogout(
                                        userSession, input, clientId, intervention);
                            }
                            // continue
                        }
                        case NO_INTERVENTION, SUSPENDED_REPROVE_ID -> {
                            // continue
                        }
                    }
                }

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
                            reproveIdentity,
                            VectorOfTrust.getRequestedLevelsOfConfidence(
                                    clientSession.getVtrList()));
                }

                URI clientRedirectURI = authenticationRequest.getRedirectionURI();
                State state = authenticationRequest.getState();
                ResponseMode responseMode = authenticationRequest.getResponseMode();

                var stateHash = getStateHash(state);
                LOG.info(
                        "Redirecting to: {} with SHA-256 of state: {}",
                        clientRedirectURI,
                        stateHash);

                CredentialTrustLevel lowestRequestedCredentialTrustLevel =
                        VectorOfTrust.getLowestCredentialTrustLevel(clientSession.getVtrList());
                if (isNull(userSession.getCurrentCredentialStrength())
                        || lowestRequestedCredentialTrustLevel.compareTo(
                                        userSession.getCurrentCredentialStrength())
                                > 0) {
                    userSession.setCurrentCredentialStrength(lowestRequestedCredentialTrustLevel);
                }

                var authCode =
                        authorisationCodeService.generateAndSaveAuthorisationCode(
                                clientSessionId, userSession.getEmailAddress(), clientSession);

                var authenticationResponse =
                        new AuthenticationSuccessResponse(
                                clientRedirectURI, authCode, null, null, state, null, responseMode);

                sessionService.save(userSession.setAuthenticated(true).setNewAccount(EXISTING));

                cloudwatchMetricsService.incrementCounter("SignIn", dimensions);
                cloudwatchMetricsService.incrementSignInByClient(
                        accountState, clientId, clientSession.getClientName(), isTestJourney);

                LOG.info("Successfully processed request");

                var metadataPairs = new ArrayList<AuditService.MetadataPair>();
                metadataPairs.add(pair("internalSubjectId", UNKNOWN));
                metadataPairs.add(pair("isNewAccount", newAccount));
                metadataPairs.add(pair("rpPairwiseId", userInfo.getClaim("rp_client_id")));
                metadataPairs.add(pair("authCode", authCode.getValue()));
                if (authenticationRequest.getNonce() != null) {
                    metadataPairs.add(pair("nonce", authenticationRequest.getNonce().getValue()));
                }

                auditService.submitAuditEvent(
                        OidcAuditableEvent.AUTH_CODE_ISSUED,
                        clientId,
                        user,
                        metadataPairs.toArray(AuditService.MetadataPair[]::new));

                return generateApiGatewayProxyResponse(
                        302,
                        "",
                        Map.of(ResponseHeaders.LOCATION, authenticationResponse.toURI().toString()),
                        null);

            } catch (UnsuccessfulCredentialResponseException e) {
                auditService.submitAuditEvent(
                        AUTH_UNSUCCESSFUL_USERINFO_RESPONSE_RECEIVED, clientId, user);
                LOG.error(
                        "Orchestration to Authentication userinfo request was not successful: {}",
                        e.getMessage());
                return RedirectService.redirectToFrontendErrorPage(authFrontend.errorURI());
            }
        } catch (AuthenticationCallbackException e) {
            LOG.warn(e.getMessage());
            return RedirectService.redirectToFrontendErrorPage(authFrontend.errorURI());
        } catch (ParseException e) {
            LOG.info("Cannot retrieve auth request params from client session id");
            return RedirectService.redirectToFrontendErrorPage(authFrontend.errorURI());
        }
    }

    private Map<String, String> buildDimensions(
            AccountState accountState,
            String clientId,
            boolean isTestJourney,
            boolean docAppJourney,
            ClientSession clientSession,
            Session userSession) {
        Map<String, String> dimensions =
                new HashMap<>(
                        Map.of(
                                "Account",
                                accountState.name(),
                                "Environment",
                                configurationService.getEnvironment(),
                                "Client",
                                clientId,
                                "IsTest",
                                Boolean.toString(isTestJourney),
                                "IsDocApp",
                                Boolean.toString(docAppJourney),
                                "ClientName",
                                clientSession.getClientName()));

        if (Objects.nonNull(userSession.getVerifiedMfaMethodType())) {
            dimensions.put("MfaMethod", userSession.getVerifiedMfaMethodType().getValue());
        } else {
            LOG.info(
                    "No mfa method to set. User is either authenticated or signing in from a low level service");
        }
        var orderedVtrList = VectorOfTrust.orderVtrList(clientSession.getVtrList());
        var mfaRequired = MfaHelper.mfaRequired(orderedVtrList);

        var levelOfConfidence = LevelOfConfidence.NONE.getValue();
        // Assumption: Requested vectors of trust will either all be for identity or none, and so we
        // can check just the first
        if (orderedVtrList.get(0).containsLevelOfConfidence()) {
            levelOfConfidence = VectorOfTrust.stringifyLevelsOfConfidence(orderedVtrList);
        }
        dimensions.put("MfaRequired", mfaRequired ? "Yes" : "No");
        dimensions.put("RequestedLevelOfConfidence", format("%s", levelOfConfidence));
        return dimensions;
    }

    private Optional<APIGatewayProxyResponseEvent>
            generateAuthenticationErrorResponseIfRequestInvalid(
                    AuthenticationRequest authenticationRequest,
                    APIGatewayProxyRequestEvent input,
                    TxmaAuditUser user,
                    Session session) {
        try {
            authorisationService.validateRequest(
                    input.getQueryStringParameters(), session.getSessionId());
        } catch (AuthenticationCallbackValidationException e) {
            return Optional.of(
                    generateAuthenticationErrorResponse(
                            authenticationRequest, input, e, user, session));
        }
        return Optional.empty();
    }

    private APIGatewayProxyResponseEvent generateAuthenticationErrorResponse(
            AuthenticationRequest authenticationRequest,
            APIGatewayProxyRequestEvent input,
            AuthenticationCallbackValidationException exception,
            TxmaAuditUser user,
            Session session) {
        var error = exception.getError();
        LOG.warn(
                "Error in Authentication Authorisation Response. ErrorCode: {}. ErrorDescription: {}.{}",
                error.getCode(),
                error.getDescription(),
                exception.getLogoutRequired() ? " Logging out." : "");
        auditService.submitAuditEvent(
                OrchestrationAuditableEvent.AUTH_UNSUCCESSFUL_CALLBACK_RESPONSE_RECEIVED,
                authenticationRequest.getClientID().getValue(),
                user);
        var errorResponseUri =
                new AuthenticationErrorResponse(
                                authenticationRequest.getRedirectionURI(),
                                error,
                                authenticationRequest.getState(),
                                authenticationRequest.getResponseMode())
                        .toURI();

        if (exception.getLogoutRequired()) {
            return logoutService.handleReauthenticationFailureLogout(
                    session,
                    input,
                    authenticationRequest.getClientID().getValue(),
                    errorResponseUri);
        } else {
            return generateApiGatewayProxyResponse(
                    302, "", Map.of(ResponseHeaders.LOCATION, errorResponseUri.toString()), null);
        }
    }

    private Long getPasswordResetTimeClaim(UserInfo userInfo) {
        Object passwordResetTimeClaim = userInfo.getClaim("password_reset_time");
        if (passwordResetTimeClaim == null) {
            LOG.info("password_reset_time claim not found");
            return 0L;
        }
        LOG.info("password_reset_time claim found");
        Long passwordResetTimeLong;
        try {
            passwordResetTimeLong = (Long) passwordResetTimeClaim;
        } catch (ClassCastException e) {
            LOG.error("Failed to cast password_reset_time claim to Long", e);
            passwordResetTimeLong = 0L;
        }
        return passwordResetTimeLong;
    }

    private static @NotNull String getStateHash(State state) {
        var stateDigest =
                new SHA256.Digest().digest(state.toString().getBytes(StandardCharsets.UTF_8));
        return new String(Hex.encode(stateDigest), StandardCharsets.UTF_8);
    }
}

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
import uk.gov.di.orchestration.shared.entity.AuthUserInfoClaims;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.ClientSession;
import uk.gov.di.orchestration.shared.entity.CredentialTrustLevel;
import uk.gov.di.orchestration.shared.entity.DestroySessionsRequest;
import uk.gov.di.orchestration.shared.entity.LevelOfConfidence;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem;
import uk.gov.di.orchestration.shared.entity.ResponseHeaders;
import uk.gov.di.orchestration.shared.entity.Session;
import uk.gov.di.orchestration.shared.entity.Session.AccountState;
import uk.gov.di.orchestration.shared.entity.VectorOfTrust;
import uk.gov.di.orchestration.shared.exceptions.NoSessionException;
import uk.gov.di.orchestration.shared.exceptions.OrchAuthCodeException;
import uk.gov.di.orchestration.shared.exceptions.UnsuccessfulCredentialResponseException;
import uk.gov.di.orchestration.shared.helpers.CookieHelper;
import uk.gov.di.orchestration.shared.helpers.IpAddressHelper;
import uk.gov.di.orchestration.shared.helpers.NowHelper;
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
import uk.gov.di.orchestration.shared.services.OrchAuthCodeService;
import uk.gov.di.orchestration.shared.services.OrchClientSessionService;
import uk.gov.di.orchestration.shared.services.OrchSessionService;
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
import static uk.gov.di.orchestration.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.orchestration.shared.helpers.AuditHelper.attachTxmaAuditFieldFromHeaders;
import static uk.gov.di.orchestration.shared.helpers.ConstructUriHelper.buildURI;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.AWS_REQUEST_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.CLIENT_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.CLIENT_SESSION_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.GOVUK_SIGNIN_JOURNEY_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.PERSISTENT_SESSION_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachSessionIdToLogs;
import static uk.gov.di.orchestration.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.orchestration.shared.services.AuditService.UNKNOWN;
import static uk.gov.di.orchestration.shared.utils.ClientSessionMigrationUtils.logIfClientSessionsAreNotEqual;

public class AuthenticationCallbackHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(AuthenticationCallbackHandler.class);
    private final ConfigurationService configurationService;
    private final AuthenticationAuthorizationService authorisationService;
    private final AuthenticationTokenService tokenService;
    private final SessionService sessionService;
    private final OrchSessionService orchSessionService;
    private final ClientSessionService clientSessionService;
    private final OrchClientSessionService orchClientSessionService;
    private final AuditService auditService;
    private final AuthenticationUserInfoStorageService userInfoStorageService;
    private final CloudwatchMetricsService cloudwatchMetricsService;
    private final AuthorisationCodeService authorisationCodeService;
    private final OrchAuthCodeService orchAuthCodeService;
    private final ClientService clientService;
    private final InitiateIPVAuthorisationService initiateIPVAuthorisationService;
    private final AccountInterventionService accountInterventionService;
    private final LogoutService logoutService;
    private final AuthFrontend authFrontend;
    private final NoSessionOrchestrationService noSessionOrchestrationService;

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
        this.orchSessionService = new OrchSessionService(configurationService);
        this.clientSessionService = new ClientSessionService(configurationService);
        this.orchClientSessionService = new OrchClientSessionService(configurationService);
        this.auditService = new AuditService(configurationService);
        this.userInfoStorageService =
                new AuthenticationUserInfoStorageService(configurationService);
        this.cloudwatchMetricsService = new CloudwatchMetricsService(configurationService);
        this.authorisationCodeService = new AuthorisationCodeService(configurationService);
        this.orchAuthCodeService = new OrchAuthCodeService(configurationService);
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
        this.noSessionOrchestrationService =
                new NoSessionOrchestrationService(configurationService);
    }

    public AuthenticationCallbackHandler(
            ConfigurationService configurationService,
            RedisConnectionService redisConnectionService) {

        var kmsConnectionService = new KmsConnectionService(configurationService);
        this.configurationService = configurationService;
        this.authorisationService = new AuthenticationAuthorizationService(redisConnectionService);
        this.tokenService =
                new AuthenticationTokenService(configurationService, kmsConnectionService);
        this.sessionService = new SessionService(configurationService, redisConnectionService);
        this.orchSessionService = new OrchSessionService(configurationService);
        this.clientSessionService =
                new ClientSessionService(configurationService, redisConnectionService);
        this.orchClientSessionService = new OrchClientSessionService(configurationService);
        this.auditService = new AuditService(configurationService);
        this.userInfoStorageService =
                new AuthenticationUserInfoStorageService(configurationService);
        this.cloudwatchMetricsService = new CloudwatchMetricsService(configurationService);
        this.authorisationCodeService =
                new AuthorisationCodeService(
                        configurationService,
                        redisConnectionService,
                        SerializationService.getInstance());
        this.orchAuthCodeService = new OrchAuthCodeService(configurationService);
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
        this.noSessionOrchestrationService =
                new NoSessionOrchestrationService(configurationService, redisConnectionService);
    }

    public AuthenticationCallbackHandler(
            ConfigurationService configurationService,
            AuthenticationAuthorizationService responseService,
            AuthenticationTokenService tokenService,
            SessionService sessionService,
            OrchSessionService orchSessionService,
            ClientSessionService clientSessionService,
            OrchClientSessionService orchClientSessionService,
            AuditService auditService,
            AuthenticationUserInfoStorageService dynamoAuthUserInfoService,
            CloudwatchMetricsService cloudwatchMetricsService,
            AuthorisationCodeService authorisationCodeService,
            OrchAuthCodeService orchAuthCodeService,
            ClientService clientService,
            InitiateIPVAuthorisationService initiateIPVAuthorisationService,
            AccountInterventionService accountInterventionService,
            LogoutService logoutService,
            AuthFrontend authFrontend,
            NoSessionOrchestrationService noSessionOrchestrationService) {
        this.configurationService = configurationService;
        this.authorisationService = responseService;
        this.tokenService = tokenService;
        this.sessionService = sessionService;
        this.orchSessionService = orchSessionService;
        this.clientSessionService = clientSessionService;
        this.orchClientSessionService = orchClientSessionService;
        this.auditService = auditService;
        this.userInfoStorageService = dynamoAuthUserInfoService;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
        this.authorisationCodeService = authorisationCodeService;
        this.orchAuthCodeService = orchAuthCodeService;
        this.clientService = clientService;
        this.initiateIPVAuthorisationService = initiateIPVAuthorisationService;
        this.accountInterventionService = accountInterventionService;
        this.logoutService = logoutService;
        this.authFrontend = authFrontend;
        this.noSessionOrchestrationService = noSessionOrchestrationService;
    }

    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        ThreadContext.clearMap();
        attachLogFieldToLogs(AWS_REQUEST_ID, context.getAwsRequestId());
        LOG.info("Request received to AuthenticationCallbackHandler");
        attachTxmaAuditFieldFromHeaders(input.getHeaders());

        if (true) {
            return RedirectService.redirectToFrontendErrorPage(
                    authFrontend.errorURI(), new Error("test error"));
        }

        try {
            CookieHelper.SessionCookieIds sessionCookiesIds =
                    CookieHelper.parseSessionCookie(input.getHeaders()).orElse(null);

            if (sessionCookiesIds == null) {
                return handleMissingSession(input);
            }

            var sessionId = sessionCookiesIds.getSessionId();
            var clientSessionId = sessionCookiesIds.getClientSessionId();
            var session =
                    sessionService
                            .getSession(sessionId)
                            .orElseThrow(
                                    () ->
                                            new AuthenticationCallbackException(
                                                    "Shared session not found in Redis"));
            var orchSession =
                    orchSessionService
                            .getSession(sessionId)
                            .orElseThrow(
                                    () ->
                                            new AuthenticationCallbackException(
                                                    "Orchestration session not found in DynamoDB"));

            attachSessionIdToLogs(sessionId);
            attachLogFieldToLogs(CLIENT_SESSION_ID, clientSessionId);
            attachLogFieldToLogs(GOVUK_SIGNIN_JOURNEY_ID, clientSessionId);

            var clientSession =
                    clientSessionService
                            .getClientSession(clientSessionId)
                            .orElseThrow(
                                    () ->
                                            new AuthenticationCallbackException(
                                                    "ClientSession not found"));
            var orchClientSession =
                    orchClientSessionService
                            .getClientSession(clientSessionId)
                            .orElseThrow(
                                    () ->
                                            new AuthenticationCallbackException(
                                                    "OrchClientSession not found"));
            logIfClientSessionsAreNotEqual(clientSession, orchClientSession);
            String persistentSessionId =
                    PersistentIdHelper.extractPersistentIdFromCookieHeader(input.getHeaders());
            attachLogFieldToLogs(PERSISTENT_SESSION_ID, persistentSessionId);

            var user =
                    TxmaAuditUser.user()
                            .withGovukSigninJourneyId(clientSessionId)
                            .withSessionId(sessionId)
                            .withPersistentSessionId(persistentSessionId);

            var authenticationRequest =
                    AuthenticationRequest.parse(orchClientSession.getAuthRequestParams());

            String clientId = authenticationRequest.getClientID().getValue();
            attachLogFieldToLogs(CLIENT_ID, clientId);

            var validationFailureResponse =
                    generateAuthenticationErrorResponseIfRequestInvalid(
                            authenticationRequest, input, user, session, sessionId, orchSession);
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
                return RedirectService.redirectToFrontendErrorPage(
                        authFrontend.errorURI(),
                        new Error(
                                String.format(
                                        "Authentication TokenResponse was not successful: %s",
                                        tokenResponse.toErrorResponse().toJSONObject())));
            }

            try {
                URI userInfoURI =
                        buildURI(
                                configurationService.getAuthenticationBackendURI().toString(),
                                "userinfo");
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

                String internalCommonSubjectId = userInfo.getSubject().getValue();

                userInfoStorageService.addAuthenticationUserInfoData(
                        internalCommonSubjectId, clientSessionId, userInfo);
                addClaimsToOrchSession(orchSession, userInfo);

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

                // TODO-922: temporary logs for checking all is working as expected
                LOG.info(
                        "is email attached to auth-external-api userinfo response: {}",
                        userInfo.getEmailAddress() != null);
                LOG.info(
                        "is verified_mfa_method_type attached to auth-external-api userinfo response: {}",
                        userInfo.getClaim(AuthUserInfoClaims.VERIFIED_MFA_METHOD_TYPE.getValue())
                                != null);
                LOG.info(
                        "is current_credential_strength attached to auth-external-api userinfo response: {}",
                        userInfo.getClaim(AuthUserInfoClaims.CURRENT_CREDENTIAL_STRENGTH.getValue())
                                != null);
                LOG.info(
                        "is uplift_required attached to auth-external-api userinfo response: {}",
                        userInfo.getClaim(AuthUserInfoClaims.UPLIFT_REQUIRED.getValue()) != null);
                LOG.info(
                        "is rpPairwiseId attached to auth-external-api userinfo response: {}",
                        userInfo.getStringClaim(AuthUserInfoClaims.RP_PAIRWISE_ID.getValue())
                                != null);
                LOG.info(
                        "is salt attached to auth-external-api userinfo response: {}",
                        userInfo.getStringClaim(AuthUserInfoClaims.SALT.getValue()) != null);
                //

                Boolean newAccount =
                        userInfo.getBooleanClaim(AuthUserInfoClaims.NEW_ACCOUNT.getValue());
                AccountState accountState = deduceAccountState(newAccount);
                OrchSessionItem.AccountState orchAccountState = deduceOrchAccountState(newAccount);
                session.setNewAccount(accountState);
                orchSession.withAccountState(orchAccountState);

                if (!orchSession.getAuthenticated() || deduceUpliftRequired(userInfo)) {
                    orchSession.setAuthTime(NowHelper.now().toInstant().getEpochSecond());
                }

                if (configurationService.supportMaxAgeEnabled()
                        && Objects.nonNull(orchSession.getPreviousSessionId())) {
                    LOG.info("Previous session id is present - handling max age");
                    handleMaxAgeSession(session, orchSession, user);
                }

                session.setAuthenticated(true);
                orchSession.setAuthenticated(true);
                clientSession.setRpPairwiseId(
                        userInfo.getStringClaim(AuthUserInfoClaims.RP_PAIRWISE_ID.getValue()));
                orchClientSession.setRpPairwiseId(
                        userInfo.getStringClaim(AuthUserInfoClaims.RP_PAIRWISE_ID.getValue()));
                orchClientSession.setPublicSubjectId(
                        userInfo.getStringClaim(AuthUserInfoClaims.PUBLIC_SUBJECT_ID.getValue()));

                sessionService.storeOrUpdateSession(session, sessionId);
                orchSessionService.updateSession(orchSession);
                clientSessionService.updateStoredClientSession(clientSessionId, clientSession);
                orchClientSessionService.updateStoredClientSession(orchClientSession);

                var docAppJourney = isDocCheckingAppUserWithSubjectId(clientSession);
                Map<String, String> dimensions =
                        buildDimensions(
                                accountState,
                                clientId,
                                isTestJourney,
                                docAppJourney,
                                clientSession,
                                userInfo.getClaim(
                                        AuthUserInfoClaims.VERIFIED_MFA_METHOD_TYPE.getValue(),
                                        String.class));

                user =
                        user.withUserId(userInfo.getSubject().getValue())
                                .withEmail(
                                        Optional.of(userInfo)
                                                .map(UserInfo::getEmailAddress)
                                                .orElse(UNKNOWN))
                                .withPhone(
                                        Optional.of(userInfo)
                                                .map(PersonClaims::getPhoneNumber)
                                                .orElse(UNKNOWN))
                                .withIpAddress(IpAddressHelper.extractIpAddress(input));

                CredentialTrustLevel requestedCredentialTrustLevel =
                        VectorOfTrust.getLowestCredentialTrustLevel(clientSession.getVtrList());
                CredentialTrustLevel credentialTrustLevel =
                        Optional.ofNullable(session.getCurrentCredentialStrength())
                                .map(
                                        sessionValue ->
                                                CredentialTrustLevel.max(
                                                        sessionValue,
                                                        requestedCredentialTrustLevel))
                                .orElse(requestedCredentialTrustLevel);

                auditService.submitAuditEvent(
                        OidcAuditableEvent.AUTHENTICATION_COMPLETE,
                        clientId,
                        user,
                        pair("new_account", newAccount),
                        pair("test_user", isTestJourney),
                        pair("credential_trust_level", credentialTrustLevel.toString()));

                cloudwatchMetricsService.incrementCounter("AuthenticationCallback", dimensions);

                var auditContext =
                        new AuditContext(
                                clientSessionId,
                                sessionId,
                                clientId,
                                internalCommonSubjectId,
                                Objects.isNull(userInfo.getEmailAddress())
                                        ? UNKNOWN
                                        : userInfo.getEmailAddress(),
                                IpAddressHelper.extractIpAddress(input),
                                Objects.isNull(userInfo.getPhoneNumber())
                                        ? UNKNOWN
                                        : userInfo.getPhoneNumber(),
                                persistentSessionId);

                Long passwordResetTime = getPasswordResetTimeClaim(userInfo);
                AccountIntervention intervention =
                        accountInterventionService.getAccountIntervention(
                                internalCommonSubjectId, passwordResetTime, auditContext);

                Boolean reproveIdentity = null;
                if (configurationService.isAccountInterventionServiceActionEnabled()) {
                    reproveIdentity = intervention.getReproveIdentity();
                    switch (intervention.getStatus()) {
                        case BLOCKED,
                                SUSPENDED_RESET_PASSWORD,
                                SUSPENDED_RESET_PASSWORD_REPROVE_ID -> {
                            return logoutService.handleAccountInterventionLogout(
                                    new DestroySessionsRequest(sessionId, session),
                                    orchSession.getInternalCommonSubjectId(),
                                    input,
                                    clientId,
                                    intervention);
                        }
                        case SUSPENDED_NO_ACTION -> {
                            if (!identityRequired) {
                                return logoutService.handleAccountInterventionLogout(
                                        new DestroySessionsRequest(sessionId, session),
                                        orchSession.getInternalCommonSubjectId(),
                                        input,
                                        clientId,
                                        intervention);
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
                            sessionId,
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
                if (isNull(session.getCurrentCredentialStrength())
                        || lowestRequestedCredentialTrustLevel.compareTo(
                                        session.getCurrentCredentialStrength())
                                > 0) {
                    session.setCurrentCredentialStrength(lowestRequestedCredentialTrustLevel);
                }

                var authCode =
                        authorisationCodeService.generateAndSaveAuthorisationCode(
                                clientId,
                                clientSessionId,
                                userInfo.getEmailAddress(),
                                orchSession.getAuthTime());

                /*
                    TODO: ATO-1218:
                     - Move the catch clause below to the bottom of this method and return the result of redirectToFrontendErrorPage (similar to the other catch clauses).
                     - Update the log in the catch clause to be level 'error' and remove Redis references (as by this point the DynamoDB store will be the primary).
                */
                try {
                    orchAuthCodeService.generateAndSaveAuthorisationCode(
                            authCode,
                            clientId,
                            clientSessionId,
                            userInfo.getEmailAddress(),
                            orchSession.getAuthTime());
                } catch (OrchAuthCodeException e) {
                    LOG.warn(
                            "Failed to generate and save authorisation code to orch auth code DynamoDB store. NOTE: Redis is still the primary at present. Error: {}",
                            e.getMessage());
                }

                var authenticationResponse =
                        new AuthenticationSuccessResponse(
                                clientRedirectURI, authCode, null, null, state, null, responseMode);

                sessionService.storeOrUpdateSession(session, sessionId);
                var currentCredentialStrength =
                        userInfo.getStringClaim(
                                AuthUserInfoClaims.CURRENT_CREDENTIAL_STRENGTH.getValue());
                if (isNull(currentCredentialStrength)
                        || lowestRequestedCredentialTrustLevel.compareTo(
                                        CredentialTrustLevel.valueOf(currentCredentialStrength))
                                > 0) {
                    orchSessionService.updateSession(
                            orchSession.withCurrentCredentialStrength(
                                    lowestRequestedCredentialTrustLevel));
                } else {
                    orchSessionService.updateSession(
                            orchSession.withCurrentCredentialStrength(
                                    CredentialTrustLevel.valueOf(currentCredentialStrength)));
                }
                // ATO-975 logging to make sure there are no differences in production
                LOG.info(
                        "Shared session current credential strength: {}",
                        session.getCurrentCredentialStrength());
                LOG.info(
                        "Orch session current credential strength: {}",
                        orchSession.getCurrentCredentialStrength());
                LOG.info(
                        "Is shared session CCS equal to Orch session CCS: {}",
                        Objects.equals(
                                session.getCurrentCredentialStrength(),
                                orchSession.getCurrentCredentialStrength()));
                cloudwatchMetricsService.incrementCounter("SignIn", dimensions);
                cloudwatchMetricsService.incrementSignInByClient(
                        orchAccountState, clientId, clientSession.getClientName(), isTestJourney);

                LOG.info("Successfully processed request");

                var metadataPairs = new ArrayList<AuditService.MetadataPair>();
                metadataPairs.add(pair("internalSubjectId", UNKNOWN));
                metadataPairs.add(pair("isNewAccount", newAccount));
                metadataPairs.add(
                        pair(
                                "rpPairwiseId",
                                userInfo.getClaim(
                                        AuthUserInfoClaims.RP_PAIRWISE_ID.getValue(),
                                        String.class)));
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
                return RedirectService.redirectToFrontendErrorPage(authFrontend.errorURI(), e);
            }
        } catch (AuthenticationCallbackException e) {
            return RedirectService.redirectToFrontendErrorPage(authFrontend.errorURI(), e);
        } catch (ParseException e) {
            return RedirectService.redirectToFrontendErrorPage(
                    authFrontend.errorURI(),
                    new Error("Cannot retrieve auth request params from client session id"));
        }
    }

    private APIGatewayProxyResponseEvent handleMissingSession(APIGatewayProxyRequestEvent input)
            throws ParseException {
        try {
            return handleCrossBrowserError(input);
        } catch (NoSessionException e) {
            throw new AuthenticationCallbackException("No session cookie found", e);
        }
    }

    private APIGatewayProxyResponseEvent handleCrossBrowserError(APIGatewayProxyRequestEvent input)
            throws NoSessionException, ParseException {
        var noSessionEntity =
                noSessionOrchestrationService.generateNoSessionOrchestrationEntity(
                        input.getQueryStringParameters());
        var authenticationRequest =
                AuthenticationRequest.parse(
                        noSessionEntity.getClientSession().getAuthRequestParams());
        auditService.submitAuditEvent(
                OrchestrationAuditableEvent.AUTH_UNSUCCESSFUL_CALLBACK_RESPONSE_RECEIVED,
                authenticationRequest.getClientID().getValue(),
                TxmaAuditUser.user()
                        .withGovukSigninJourneyId(noSessionEntity.getClientSessionId()));
        var errorResponse =
                new AuthenticationErrorResponse(
                        authenticationRequest.getRedirectionURI(),
                        noSessionEntity.getErrorObject(),
                        authenticationRequest.getState(),
                        authenticationRequest.getResponseMode());
        return generateApiGatewayProxyResponse(
                302, "", Map.of(ResponseHeaders.LOCATION, errorResponse.toURI().toString()), null);
    }

    private boolean deduceUpliftRequired(UserInfo userInfo) {
        Boolean upliftRequiredClaim =
                userInfo.getBooleanClaim(AuthUserInfoClaims.UPLIFT_REQUIRED.getValue());
        if (upliftRequiredClaim == null) {
            LOG.error(
                    "uplift_required claim is null in userinfo response. Defaulting value to false.");
            return false;
        } else {
            return upliftRequiredClaim;
        }
    }

    private AccountState deduceAccountState(Boolean newAccount) {
        AccountState accountState;
        if (newAccount == null) {
            accountState = AccountState.UNKNOWN;
        } else {
            accountState = newAccount ? AccountState.NEW : AccountState.EXISTING;
        }
        return accountState;
    }

    private OrchSessionItem.AccountState deduceOrchAccountState(Boolean newAccount) {
        OrchSessionItem.AccountState accountState;
        if (newAccount == null) {
            accountState = OrchSessionItem.AccountState.UNKNOWN;
        } else {
            accountState =
                    newAccount
                            ? OrchSessionItem.AccountState.NEW
                            : OrchSessionItem.AccountState.EXISTING;
        }
        return accountState;
    }

    private Map<String, String> buildDimensions(
            AccountState accountState,
            String clientId,
            boolean isTestJourney,
            boolean docAppJourney,
            ClientSession clientSession,
            String verifiedMfaMethodType) {
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

        if (Objects.nonNull(verifiedMfaMethodType)) {
            dimensions.put("MfaMethod", verifiedMfaMethodType);
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
                    Session session,
                    String sessionId,
                    OrchSessionItem orchSession) {
        try {
            authorisationService.validateRequest(input.getQueryStringParameters(), sessionId);
        } catch (AuthenticationCallbackValidationException e) {
            return Optional.of(
                    generateAuthenticationErrorResponse(
                            authenticationRequest,
                            input,
                            e,
                            user,
                            session,
                            sessionId,
                            orchSession));
        }
        return Optional.empty();
    }

    private APIGatewayProxyResponseEvent generateAuthenticationErrorResponse(
            AuthenticationRequest authenticationRequest,
            APIGatewayProxyRequestEvent input,
            AuthenticationCallbackValidationException exception,
            TxmaAuditUser user,
            Session session,
            String sessionId,
            OrchSessionItem orchSession) {
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
                    new DestroySessionsRequest(sessionId, session),
                    orchSession.getInternalCommonSubjectId(),
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

    private void addClaimsToOrchSession(OrchSessionItem orchSession, UserInfo userInfo) {
        String verifiedMfaMethodType =
                userInfo.getClaim(
                        AuthUserInfoClaims.VERIFIED_MFA_METHOD_TYPE.getValue(), String.class);
        String internalCommonSubjectId = userInfo.getSubject().getValue();

        OrchSessionItem updatedOrchSession =
                orchSession
                        .withVerifiedMfaMethodType(verifiedMfaMethodType)
                        .withInternalCommonSubjectId(internalCommonSubjectId);

        LOG.info("Updating Orch session with claims from userinfo response");
        // TODO-922: temporary logs for checking all is working as expected
        LOG.info(
                "is internalCommonSubjectId attached to orch session: {}",
                orchSession.getInternalCommonSubjectId() != null);
        //
        orchSessionService.updateSession(updatedOrchSession);
    }

    private void handleMaxAgeSession(
            Session currentSharedSession, OrchSessionItem currentOrchSession, TxmaAuditUser user) {
        var previousSessionId = currentOrchSession.getPreviousSessionId();
        var previousSharedSession = sessionService.getSession(previousSessionId);
        var previousOrchSession = orchSessionService.getSession(previousSessionId);

        if (previousSharedSession.isEmpty() || previousOrchSession.isEmpty()) {
            LOG.warn(
                    "Cannot retrieve previous OrchSession or previous shared session required for to handle max_age");
            currentOrchSession.setPreviousSessionId(null);
            return;
        }

        var previousInternalCommonSubjectId =
                previousOrchSession.get().getInternalCommonSubjectId();

        if (currentOrchSession
                .getInternalCommonSubjectId()
                .equals(previousInternalCommonSubjectId)) {
            LOG.info("Previous OrchSession InternalCommonSubjectId matches Auth UserInfo response");
            previousSharedSession
                    .get()
                    .getClientSessions()
                    .forEach(currentSharedSession::addClientSession);

        } else {
            LOG.info(
                    "Previous OrchSession InternalCommonSubjectId does not match Auth UserInfo response");
            logoutService.handleMaxAgeLogout(
                    new DestroySessionsRequest(previousSessionId, previousSharedSession.get()),
                    previousOrchSession.get(),
                    user);
        }
        currentOrchSession.setPreviousSessionId(null);
    }
}

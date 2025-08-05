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
import uk.gov.di.orchestration.shared.entity.CredentialTrustLevel;
import uk.gov.di.orchestration.shared.entity.DestroySessionsRequest;
import uk.gov.di.orchestration.shared.entity.LevelOfConfidence;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem;
import uk.gov.di.orchestration.shared.entity.ResponseHeaders;
import uk.gov.di.orchestration.shared.entity.VectorOfTrust;
import uk.gov.di.orchestration.shared.exceptions.NoSessionException;
import uk.gov.di.orchestration.shared.exceptions.OrchAuthCodeException;
import uk.gov.di.orchestration.shared.exceptions.SessionNotFoundException;
import uk.gov.di.orchestration.shared.exceptions.UnsuccessfulCredentialResponseException;
import uk.gov.di.orchestration.shared.helpers.CookieHelper;
import uk.gov.di.orchestration.shared.helpers.IpAddressHelper;
import uk.gov.di.orchestration.shared.helpers.NowHelper;
import uk.gov.di.orchestration.shared.helpers.PersistentIdHelper;
import uk.gov.di.orchestration.shared.services.AccountInterventionService;
import uk.gov.di.orchestration.shared.services.AuditService;
import uk.gov.di.orchestration.shared.services.AuthenticationUserInfoStorageService;
import uk.gov.di.orchestration.shared.services.ClientService;
import uk.gov.di.orchestration.shared.services.CloudwatchMetricsService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.CrossBrowserOrchestrationService;
import uk.gov.di.orchestration.shared.services.DynamoClientService;
import uk.gov.di.orchestration.shared.services.KmsConnectionService;
import uk.gov.di.orchestration.shared.services.LogoutService;
import uk.gov.di.orchestration.shared.services.OrchAuthCodeService;
import uk.gov.di.orchestration.shared.services.OrchClientSessionService;
import uk.gov.di.orchestration.shared.services.OrchSessionService;
import uk.gov.di.orchestration.shared.services.RedirectService;
import uk.gov.di.orchestration.shared.services.RedisConnectionService;
import uk.gov.di.orchestration.shared.services.StateStorageService;
import uk.gov.di.orchestration.shared.services.TokenService;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import static com.nimbusds.oauth2.sdk.http.HTTPRequest.Method.GET;
import static java.lang.String.format;
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
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachTraceId;
import static uk.gov.di.orchestration.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.orchestration.shared.services.AuditService.UNKNOWN;

public class AuthenticationCallbackHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(AuthenticationCallbackHandler.class);
    private final ConfigurationService configurationService;
    private final AuthenticationAuthorizationService authorisationService;
    private final AuthenticationTokenService tokenService;
    private final OrchSessionService orchSessionService;
    private final OrchClientSessionService orchClientSessionService;
    private final AuditService auditService;
    private final AuthenticationUserInfoStorageService userInfoStorageService;
    private final CloudwatchMetricsService cloudwatchMetricsService;
    private final OrchAuthCodeService orchAuthCodeService;
    private final ClientService clientService;
    private final InitiateIPVAuthorisationService initiateIPVAuthorisationService;
    private final AccountInterventionService accountInterventionService;
    private final LogoutService logoutService;
    private final AuthFrontend authFrontend;
    private final CrossBrowserOrchestrationService crossBrowserOrchestrationService;

    public AuthenticationCallbackHandler() {
        this(ConfigurationService.getInstance());
    }

    public AuthenticationCallbackHandler(ConfigurationService configurationService) {
        var kmsConnectionService = new KmsConnectionService(configurationService);
        var redisConnectionService = new RedisConnectionService(configurationService);
        var stateStorageService = new StateStorageService(configurationService);
        var oidcApi = new OidcAPI(configurationService);
        this.configurationService = configurationService;
        this.authorisationService = new AuthenticationAuthorizationService(stateStorageService);
        this.tokenService =
                new AuthenticationTokenService(configurationService, kmsConnectionService);
        this.orchSessionService = new OrchSessionService(configurationService);
        this.orchClientSessionService = new OrchClientSessionService(configurationService);
        this.auditService = new AuditService(configurationService);
        this.userInfoStorageService =
                new AuthenticationUserInfoStorageService(configurationService);
        this.cloudwatchMetricsService = new CloudwatchMetricsService(configurationService);
        this.orchAuthCodeService = new OrchAuthCodeService(configurationService);
        this.clientService = new DynamoClientService(configurationService);

        this.initiateIPVAuthorisationService =
                new InitiateIPVAuthorisationService(
                        configurationService,
                        auditService,
                        new IPVAuthorisationService(configurationService, kmsConnectionService),
                        cloudwatchMetricsService,
                        new CrossBrowserOrchestrationService(configurationService),
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
        this.crossBrowserOrchestrationService =
                new CrossBrowserOrchestrationService(configurationService);
    }

    public AuthenticationCallbackHandler(
            ConfigurationService configurationService,
            RedisConnectionService redisConnectionService) {

        var stateStorageService = new StateStorageService(configurationService);
        var kmsConnectionService = new KmsConnectionService(configurationService);
        this.configurationService = configurationService;
        this.authorisationService = new AuthenticationAuthorizationService(stateStorageService);
        this.tokenService =
                new AuthenticationTokenService(configurationService, kmsConnectionService);
        this.orchSessionService = new OrchSessionService(configurationService);
        this.orchClientSessionService = new OrchClientSessionService(configurationService);
        this.auditService = new AuditService(configurationService);
        this.userInfoStorageService =
                new AuthenticationUserInfoStorageService(configurationService);
        this.cloudwatchMetricsService = new CloudwatchMetricsService(configurationService);
        this.orchAuthCodeService = new OrchAuthCodeService(configurationService);
        this.clientService = new DynamoClientService(configurationService);
        this.initiateIPVAuthorisationService =
                new InitiateIPVAuthorisationService(
                        configurationService,
                        auditService,
                        new IPVAuthorisationService(configurationService, kmsConnectionService),
                        cloudwatchMetricsService,
                        new CrossBrowserOrchestrationService(
                                configurationService, redisConnectionService),
                        new TokenService(
                                configurationService,
                                redisConnectionService,
                                kmsConnectionService,
                                new OidcAPI(configurationService)));
        this.accountInterventionService =
                new AccountInterventionService(
                        configurationService, cloudwatchMetricsService, auditService);
        this.logoutService = new LogoutService(configurationService);
        this.authFrontend = new AuthFrontend(configurationService);
        this.crossBrowserOrchestrationService =
                new CrossBrowserOrchestrationService(configurationService, redisConnectionService);
    }

    public AuthenticationCallbackHandler(
            ConfigurationService configurationService,
            AuthenticationAuthorizationService responseService,
            AuthenticationTokenService tokenService,
            OrchSessionService orchSessionService,
            OrchClientSessionService orchClientSessionService,
            AuditService auditService,
            AuthenticationUserInfoStorageService dynamoAuthUserInfoService,
            CloudwatchMetricsService cloudwatchMetricsService,
            OrchAuthCodeService orchAuthCodeService,
            ClientService clientService,
            InitiateIPVAuthorisationService initiateIPVAuthorisationService,
            AccountInterventionService accountInterventionService,
            LogoutService logoutService,
            AuthFrontend authFrontend,
            CrossBrowserOrchestrationService crossBrowserOrchestrationService) {
        this.configurationService = configurationService;
        this.authorisationService = responseService;
        this.tokenService = tokenService;
        this.orchSessionService = orchSessionService;
        this.orchClientSessionService = orchClientSessionService;
        this.auditService = auditService;
        this.userInfoStorageService = dynamoAuthUserInfoService;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
        this.orchAuthCodeService = orchAuthCodeService;
        this.clientService = clientService;
        this.initiateIPVAuthorisationService = initiateIPVAuthorisationService;
        this.accountInterventionService = accountInterventionService;
        this.logoutService = logoutService;
        this.authFrontend = authFrontend;
        this.crossBrowserOrchestrationService = crossBrowserOrchestrationService;
    }

    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        ThreadContext.clearMap();
        attachTraceId();
        attachLogFieldToLogs(AWS_REQUEST_ID, context.getAwsRequestId());
        LOG.info("Request received to AuthenticationCallbackHandler");
        attachTxmaAuditFieldFromHeaders(input.getHeaders());

        try {
            CookieHelper.SessionCookieIds sessionCookiesIds =
                    CookieHelper.parseSessionCookie(input.getHeaders()).orElse(null);

            if (sessionCookiesIds == null) {
                return handleCrossBrowserError(input);
            }

            var sessionId = sessionCookiesIds.getSessionId();
            var clientSessionId = sessionCookiesIds.getClientSessionId();
            var orchSession =
                    orchSessionService
                            .getSession(sessionId)
                            .orElseThrow(
                                    () ->
                                            new SessionNotFoundException(
                                                    "Orchestration session not found in DynamoDB"));

            attachSessionIdToLogs(sessionId);
            attachLogFieldToLogs(CLIENT_SESSION_ID, clientSessionId);
            attachLogFieldToLogs(GOVUK_SIGNIN_JOURNEY_ID, clientSessionId);

            var orchClientSession =
                    orchClientSessionService
                            .getClientSession(clientSessionId)
                            .orElseThrow(
                                    () ->
                                            new AuthenticationCallbackException(
                                                    "OrchClientSession not found"));
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
                            authenticationRequest, input, user, sessionId, orchSession);
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
                                orchClientSession.getAuthRequestParams(),
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
                OrchSessionItem.AccountState orchAccountState = deduceOrchAccountState(newAccount);
                orchSession.withAccountState(orchAccountState);

                if (!orchSession.getAuthenticated() || deduceUpliftRequired(userInfo)) {
                    orchSession.setAuthTime(NowHelper.now().toInstant().getEpochSecond());
                }

                if (Objects.nonNull(orchSession.getPreviousSessionId())) {
                    LOG.info("Previous session id is present - handling max age");
                    handleMaxAgeSession(orchSession, user);
                }

                orchSession.setAuthenticated(true);
                orchClientSession.setRpPairwiseId(
                        userInfo.getStringClaim(AuthUserInfoClaims.RP_PAIRWISE_ID.getValue()));
                orchClientSession.setPublicSubjectId(
                        userInfo.getStringClaim(AuthUserInfoClaims.PUBLIC_SUBJECT_ID.getValue()));

                orchSessionService.updateSession(orchSession);
                orchClientSessionService.updateStoredClientSession(orchClientSession);

                var docAppJourney = isDocCheckingAppUserWithSubjectId(orchClientSession);
                Map<String, String> dimensions =
                        buildDimensions(
                                orchAccountState,
                                clientId,
                                orchClientSession.getClientName(),
                                orchClientSession.getVtrList(),
                                isTestJourney,
                                docAppJourney,
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

                CredentialTrustLevel lowestRequestedCredentialTrustLevel =
                        VectorOfTrust.getLowestCredentialTrustLevel(orchClientSession.getVtrList());
                CredentialTrustLevel credentialTrustLevel =
                        Optional.ofNullable(
                                        userInfo.getStringClaim(
                                                AuthUserInfoClaims.ACHIEVED_CREDENTIAL_STRENGTH
                                                        .getValue()))
                                .map(CredentialTrustLevel::valueOf)
                                .map(
                                        achievedCredentialTrust ->
                                                CredentialTrustLevel.max(
                                                        achievedCredentialTrust,
                                                        lowestRequestedCredentialTrustLevel))
                                .orElse(lowestRequestedCredentialTrustLevel);

                logComparisonRequestCredentialTrustAndAchieved(
                        userInfo, lowestRequestedCredentialTrustLevel);

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
                                    new DestroySessionsRequest(sessionId, orchSession),
                                    orchSession.getInternalCommonSubjectId(),
                                    input,
                                    clientId,
                                    intervention);
                        }
                        case SUSPENDED_NO_ACTION -> {
                            if (!identityRequired) {
                                return logoutService.handleAccountInterventionLogout(
                                        new DestroySessionsRequest(sessionId, orchSession),
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
                                    orchClientSession.getVtrList()));
                }

                URI clientRedirectURI = authenticationRequest.getRedirectionURI();
                State state = authenticationRequest.getState();
                ResponseMode responseMode = authenticationRequest.getResponseMode();

                var stateHash = getStateHash(state);
                LOG.info(
                        "Redirecting to: {} with SHA-256 of state: {}",
                        clientRedirectURI,
                        stateHash);

                var authCode =
                        orchAuthCodeService.generateAndSaveAuthorisationCode(
                                clientId,
                                clientSessionId,
                                userInfo.getEmailAddress(),
                                orchSession.getAuthTime());

                var authenticationResponse =
                        new AuthenticationSuccessResponse(
                                clientRedirectURI, authCode, null, null, state, null, responseMode);

                orchSessionService.updateSession(orchSession);

                cloudwatchMetricsService.incrementCounter("SignIn", dimensions);
                cloudwatchMetricsService.incrementSignInByClient(
                        orchAccountState,
                        clientId,
                        orchClientSession.getClientName(),
                        isTestJourney);

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
        } catch (AuthenticationCallbackException | OrchAuthCodeException e) {
            return RedirectService.redirectToFrontendErrorPage(authFrontend.errorURI(), e);
        } catch (ParseException e) {
            return RedirectService.redirectToFrontendErrorPage(
                    authFrontend.errorURI(),
                    new Error("Cannot retrieve auth request params from client session id"));
        } catch (NoSessionException | SessionNotFoundException e) {
            return RedirectService.redirectToFrontendErrorPageForNoSession(
                    authFrontend.errorURI(), e);
        }
    }

    private APIGatewayProxyResponseEvent handleCrossBrowserError(APIGatewayProxyRequestEvent input)
            throws NoSessionException, ParseException {
        var noSessionEntity =
                crossBrowserOrchestrationService.generateNoSessionOrchestrationEntity(
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
            OrchSessionItem.AccountState accountState,
            String clientId,
            String clientName,
            List<VectorOfTrust> vtrList,
            boolean isTestJourney,
            boolean docAppJourney,
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
                                clientName));

        if (Objects.nonNull(verifiedMfaMethodType)) {
            dimensions.put("MfaMethod", verifiedMfaMethodType);
        } else {
            LOG.info(
                    "No mfa method to set. User is either authenticated or signing in from a low level service");
        }
        var orderedVtrList = VectorOfTrust.orderVtrList(vtrList);
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
                    String sessionId,
                    OrchSessionItem orchSession) {
        try {
            authorisationService.validateRequest(input.getQueryStringParameters(), sessionId);
        } catch (AuthenticationCallbackValidationException e) {
            return Optional.of(
                    generateAuthenticationErrorResponse(
                            authenticationRequest, input, e, user, sessionId, orchSession));
        }
        return Optional.empty();
    }

    private APIGatewayProxyResponseEvent generateAuthenticationErrorResponse(
            AuthenticationRequest authenticationRequest,
            APIGatewayProxyRequestEvent input,
            AuthenticationCallbackValidationException exception,
            TxmaAuditUser user,
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
                    new DestroySessionsRequest(sessionId, orchSession),
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

    private void handleMaxAgeSession(OrchSessionItem currentOrchSession, TxmaAuditUser user) {
        var previousSessionId = currentOrchSession.getPreviousSessionId();
        var previousOrchSession = orchSessionService.getSession(previousSessionId);

        if (previousOrchSession.isEmpty()) {
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

            previousOrchSession
                    .get()
                    .getClientSessions()
                    .forEach(currentOrchSession::addClientSession);

        } else {
            LOG.info(
                    "Previous OrchSession InternalCommonSubjectId does not match Auth UserInfo response");
            logoutService.handleMaxAgeLogout(
                    new DestroySessionsRequest(previousSessionId, previousOrchSession.get()),
                    previousOrchSession.get(),
                    user);
        }
        currentOrchSession.setPreviousSessionId(null);
    }

    private void logComparisonRequestCredentialTrustAndAchieved(
            UserInfo authUserInfo, CredentialTrustLevel requestedCredentialStrength) {
        // TODO: This logging currently looks fine but in future we should validate that
        // this value is non-null and >= the requested credential strength
        try {
            var userInfoAchievedCredentialStrength =
                    authUserInfo.getStringClaim(
                            AuthUserInfoClaims.ACHIEVED_CREDENTIAL_STRENGTH.getValue());
            var isAchievedCredentialStrengthNull =
                    Objects.isNull(userInfoAchievedCredentialStrength);

            LOG.info("Is Achieved Credential strength null: {}", isAchievedCredentialStrengthNull);
            LOG.info("Lowest requested credential strength value: {}", requestedCredentialStrength);
            if (isAchievedCredentialStrengthNull) {
                return;
            }

            var achievedCredentialStrength =
                    CredentialTrustLevel.valueOf(userInfoAchievedCredentialStrength);
            var isEqualToOrHigherThanRequested =
                    achievedCredentialStrength.equals(requestedCredentialStrength)
                            || achievedCredentialStrength.isHigherThan(requestedCredentialStrength);

            LOG.info("Achieved credential strength value: {}", achievedCredentialStrength);
            LOG.info(
                    "Is Achieved credential strength higher or equal to requested value: {}",
                    isEqualToOrHigherThanRequested);

        } catch (Exception e) {
            LOG.warn(
                    "Exception when trying to compare requested and achieved credential strength levels: {}. Continuing as normal",
                    e.getMessage());
        }
    }
}

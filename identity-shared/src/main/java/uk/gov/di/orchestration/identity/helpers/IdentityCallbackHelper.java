package uk.gov.di.orchestration.identity.helpers;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.audit.AuditContext;
import uk.gov.di.orchestration.audit.TxmaAuditUser;
import uk.gov.di.orchestration.identity.entity.IdentityAuditEventConfiguration;
import uk.gov.di.orchestration.identity.entity.IdentityProgressStatus;
import uk.gov.di.orchestration.identity.entity.LogIds;
import uk.gov.di.orchestration.identity.entity.SPOTClaims;
import uk.gov.di.orchestration.identity.entity.SPOTRequest;
import uk.gov.di.orchestration.identity.services.IdentityProgressService;
import uk.gov.di.orchestration.shared.api.CommonFrontend;
import uk.gov.di.orchestration.shared.api.OidcAPI;
import uk.gov.di.orchestration.shared.entity.AccountIntervention;
import uk.gov.di.orchestration.shared.entity.AuthUserInfoClaims;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.DestroySessionsRequest;
import uk.gov.di.orchestration.shared.entity.IdentityClaims;
import uk.gov.di.orchestration.shared.entity.OrchClientSessionItem;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem;
import uk.gov.di.orchestration.shared.entity.ResponseHeaders;
import uk.gov.di.orchestration.shared.entity.ValidClaims;
import uk.gov.di.orchestration.shared.helpers.ConstructUriHelper;
import uk.gov.di.orchestration.shared.helpers.NowHelper;
import uk.gov.di.orchestration.shared.services.AccountInterventionService;
import uk.gov.di.orchestration.shared.services.AuditService;
import uk.gov.di.orchestration.shared.services.AuthCodeResponseGenerationService;
import uk.gov.di.orchestration.shared.services.AuthenticationUserInfoStorageService;
import uk.gov.di.orchestration.shared.services.AwsSqsClient;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.DynamoIdentityService;
import uk.gov.di.orchestration.shared.services.LogoutService;
import uk.gov.di.orchestration.shared.services.Metrics;
import uk.gov.di.orchestration.shared.services.OrchAuthCodeService;
import uk.gov.di.orchestration.shared.services.OrchSessionService;
import uk.gov.di.orchestration.shared.services.RedirectService;
import uk.gov.di.orchestration.shared.services.SerializationService;

import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import static uk.gov.di.orchestration.identity.utils.IdentityCallbackUtils.returnCodePresentInResponse;
import static uk.gov.di.orchestration.identity.utils.IdentityCallbackUtils.rpRequestedReturnCode;
import static uk.gov.di.orchestration.identity.utils.IdentityCallbackUtils.sendUserIdentityRequest;
import static uk.gov.di.orchestration.identity.utils.IdentityCallbackUtils.validateUserIdentityResponse;
import static uk.gov.di.orchestration.shared.entity.IdentityClaims.VOT;
import static uk.gov.di.orchestration.shared.entity.ValidClaims.RETURN_CODE;
import static uk.gov.di.orchestration.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.orchestration.shared.helpers.ClientSubjectHelper.getSectorIdentifierForClient;
import static uk.gov.di.orchestration.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.orchestration.shared.services.AuditService.MetadataPair.pair;

public class IdentityCallbackHelper {
    private static final Logger LOG = LogManager.getLogger(IdentityCallbackHelper.class);
    private static final SerializationService objectMapper = SerializationService.getInstance();
    private final ConfigurationService configurationService;
    private final AuthenticationUserInfoStorageService authUserInfoStorageService;
    private final AuditService auditService;
    private final CommonFrontend frontend;
    private final IdentityProgressService identityProgressService;
    private final TokenService tokenService;
    private final OidcAPI oidcAPI;
    private final AuthCodeResponseGenerationService authCodeResponseService;
    private final OrchAuthCodeService orchAuthCodeService;
    private final Metrics metrics;
    private final DynamoIdentityService dynamoIdentityService;
    private final AwsSqsClient spotSqsClient;
    private final OrchSessionService orchSessionService;
    private final LogoutService logoutService;
    private final AccountInterventionService accountInterventionService;
    private final IdentityAuditEventConfiguration auditEventConfiguration;

    public IdentityCallbackHelper(
            ConfigurationService configurationService,
            AuthenticationUserInfoStorageService authUserInfoStorageService,
            AuditService auditService,
            CommonFrontend frontend,
            IdentityProgressService identityProgressService,
            TokenService tokenService,
            OidcAPI oidcAPI,
            AuthCodeResponseGenerationService authCodeResponseService,
            OrchAuthCodeService orchAuthCodeService,
            Metrics metrics,
            DynamoIdentityService dynamoIdentityService,
            AwsSqsClient spotSqsClient,
            OrchSessionService orchSessionService,
            LogoutService logoutService,
            AccountInterventionService accountInterventionService,
            IdentityAuditEventConfiguration auditEventConfiguration) {
        this.configurationService = configurationService;
        this.authUserInfoStorageService = authUserInfoStorageService;
        this.auditService = auditService;
        this.frontend = frontend;
        this.identityProgressService = identityProgressService;
        this.tokenService = tokenService;
        this.oidcAPI = oidcAPI;
        this.authCodeResponseService = authCodeResponseService;
        this.orchAuthCodeService = orchAuthCodeService;
        this.metrics = metrics;
        this.dynamoIdentityService = dynamoIdentityService;
        this.spotSqsClient = spotSqsClient;
        this.orchSessionService = orchSessionService;
        this.logoutService = logoutService;
        this.accountInterventionService = accountInterventionService;
        this.auditEventConfiguration = auditEventConfiguration;
    }

    public APIGatewayProxyResponseEvent test(
            OrchSessionItem orchSession,
            OrchClientSessionItem orchClientSession,
            ClientRegistry clientRegistry,
            String persistentId,
            String ipAddress,
            String authCode,
            AuthenticationRequest authRequest,
            String awsRequestId)
            throws Exception {
        var clientSessionId = orchClientSession.getClientSessionId();
        var sessionId = orchSession.getSessionId();
        var clientId = clientRegistry.getClientID();
        var authUserInfo =
                getAuthUserInfo(
                                orchSession.getInternalCommonSubjectId(),
                                orchClientSession.getClientSessionId())
                        .orElseThrow(() -> new /*IpvCallback*/ Exception("authUserInfo not found"));

        var auditContext =
                new AuditContext(
                        clientSessionId,
                        sessionId,
                        clientId,
                        orchSession.getInternalCommonSubjectId(),
                        authUserInfo.getEmailAddress(),
                        ipAddress,
                        Objects.isNull(authUserInfo.getPhoneNumber())
                                ? AuditService.UNKNOWN
                                : authUserInfo.getPhoneNumber(),
                        persistentId);

        var rpPairwiseSubject =
                new Subject(
                        orchClientSession.getCorrectPairwiseIdGivenSubjectType(
                                clientRegistry.getSubjectType()));

        var user =
                TxmaAuditUser.user()
                        .withGovukSigninJourneyId(clientSessionId)
                        .withSessionId(sessionId)
                        .withUserId(orchSession.getInternalCommonSubjectId())
                        .withEmail(authUserInfo.getEmailAddress())
                        .withPhone(
                                Objects.isNull(authUserInfo.getPhoneNumber())
                                        ? AuditService.UNKNOWN
                                        : authUserInfo.getPhoneNumber())
                        .withPersistentSessionId(persistentId);

        auditService.submitAuditEvent(
                auditEventConfiguration.authResponseReceived(), clientId, user);

        var tokenResponse =
                segmentedFunctionCall("getToken", () -> tokenService.getToken(authCode));
        if (!tokenResponse.indicatesSuccess()) {
            auditService.submitAuditEvent(
                    auditEventConfiguration.unsuccessfulTokenResponseReceived(), clientId, user);
            return RedirectService.redirectToFrontendErrorPageWithErrorLog(
                    frontend.errorURI(),
                    new Exception(
                            String.format(
                                    "TokenResponse was not successful: %s",
                                    tokenResponse.toErrorResponse().toJSONObject())));
        }
        auditService.submitAuditEvent(
                auditEventConfiguration.successfulTokenResponseReceived(), clientId, user);

        var userIdentityUserInfo =
                sendUserIdentityRequest(
                        new UserInfoRequest(
                                ConstructUriHelper.buildURI(
                                        configurationService.getIPVBackendURI().toString(),
                                        "user-identity"),
                                tokenResponse
                                        .toSuccessResponse()
                                        .getTokens()
                                        .getBearerAccessToken()));

        auditService.submitAuditEvent(
                auditEventConfiguration.successfulIdentityResponseReceived(), clientId, user);
        var vtrList = orchClientSession.getVtrList();
        var userIdentityError =
                validateUserIdentityResponse(
                        userIdentityUserInfo, vtrList, oidcAPI.trustmarkURI().toString());
        if (userIdentityError.isPresent()) {
            var aisResponseOpt =
                    checkForAisIntervention(
                            orchSession,
                            auditContext,
                            ipAddress,
                            persistentId,
                            clientSessionId,
                            clientId);
            if (aisResponseOpt.isPresent()) {
                return aisResponseOpt.get();
            }
            var returnCode = userIdentityUserInfo.getClaim(RETURN_CODE.getValue());
            if (returnCodePresentInResponse(returnCode)) {
                if (rpRequestedReturnCode(clientRegistry, authRequest)) {
                    LOG.info("Generating auth code response for return code(s)");

                    var authenticationResponse =
                            generateReturnCodeAuthenticationResponse(
                                    authRequest,
                                    orchSession,
                                    orchClientSession,
                                    userIdentityUserInfo,
                                    ipAddress,
                                    persistentId,
                                    clientId,
                                    authUserInfo.getEmailAddress(),
                                    authUserInfo.getStringClaim(
                                            AuthUserInfoClaims.LOCAL_ACCOUNT_ID.getValue()));
                    return generateApiGatewayProxyResponse(
                            302,
                            "",
                            Map.of(
                                    ResponseHeaders.LOCATION,
                                    authenticationResponse.toURI().toString()),
                            null);
                } else {
                    LOG.warn("SPOT will not be invoked. Returning Error to RP");
                    var errorResponse =
                            new AuthenticationErrorResponse(
                                    authRequest.getRedirectionURI(),
                                    OAuth2Error.ACCESS_DENIED,
                                    authRequest.getState(),
                                    authRequest.getResponseMode());
                    return generateApiGatewayProxyResponse(
                            302,
                            "",
                            Map.of(ResponseHeaders.LOCATION, errorResponse.toURI().toString()),
                            null);
                }
            }

            LOG.warn("SPOT will not be invoked. Returning Error to RP");
            var errorResponse =
                    new AuthenticationErrorResponse(
                            authRequest.getRedirectionURI(),
                            userIdentityError.get(),
                            authRequest.getState(),
                            authRequest.getResponseMode());
            return generateApiGatewayProxyResponse(
                    302,
                    "",
                    Map.of(ResponseHeaders.LOCATION, errorResponse.toURI().toString()),
                    null);
        }

        LOG.info("SPOT will be invoked.");
        var logIds = new LogIds(sessionId, persistentId, awsRequestId, clientId, clientSessionId);
        queueSPOTRequest(
                logIds,
                getSectorIdentifierForClient(
                        clientRegistry, configurationService.getInternalSectorURI()),
                authUserInfo,
                rpPairwiseSubject,
                userIdentityUserInfo,
                clientId);

        var spotQueuedAt = NowHelper.now().toInstant().toEpochMilli();

        auditService.submitAuditEvent(auditEventConfiguration.spotRequested(), clientId, user);
        segmentedFunctionCall(
                "saveIdentityClaims",
                () ->
                        saveIdentityClaimsToDynamo(
                                clientSessionId,
                                rpPairwiseSubject,
                                userIdentityUserInfo,
                                spotQueuedAt));

        URI redirectURI = null;
        if (configurationService.isSyncWaitForSpotEnabled()) {
            var status = identityProgressService.pollForStatus(clientSessionId, auditContext);
            if (status == IdentityProgressStatus.NO_ENTRY) {
                return RedirectService.redirectToFrontendErrorPageWithErrorLog(
                        frontend.errorURI(), new Error("Identity processing failed"));
            }
            if (status == IdentityProgressStatus.ERROR) {
                return RedirectService.redirectToFrontendErrorPageWithErrorLog(
                        frontend.errorURI(), new Error("Identity processing returned NO_ENTRY"));
            }
            if (status == IdentityProgressStatus.COMPLETED) {
                var aisResponseOpt =
                        checkForAisIntervention(
                                orchSession,
                                auditContext,
                                ipAddress,
                                persistentId,
                                clientSessionId,
                                clientId);
                if (aisResponseOpt.isPresent()) {
                    return aisResponseOpt.get();
                }
                redirectURI =
                        generateAuthenticationResponse(
                                        authRequest,
                                        orchSession,
                                        clientSessionId,
                                        ipAddress,
                                        persistentId,
                                        clientId,
                                        clientRegistry.getClientName(),
                                        authUserInfo.getEmailAddress(),
                                        authUserInfo.getSubject().getValue(),
                                        rpPairwiseSubject.getValue(),
                                        orchSession.getInternalCommonSubjectId())
                                .toURI();
            }
        } else {
            redirectURI = frontend.ipvCallbackURI();
            LOG.info("Successful IPV callback. Redirecting to frontend");
        }
        if (redirectURI == null) {
            // Should be impossible, but compiler seems to think otherwise
            return RedirectService.redirectToFrontendErrorPageWithErrorLog(
                    frontend.errorURI(), new Error("Failed to create redirectURI"));
        }
        return null;
    }

    private Optional<UserInfo> getAuthUserInfo(
            String internalCommonSubjectId, String clientSessionId) {

        if (internalCommonSubjectId == null || internalCommonSubjectId.isBlank()) {
            LOG.warn("internalCommonSubjectId is null or empty");
            return Optional.empty();
        }

        try {
            return authUserInfoStorageService.getAuthenticationUserInfo(
                    internalCommonSubjectId, clientSessionId);
        } catch (ParseException e) {
            LOG.warn("error parsing authUserInfo. Message: {}", e.getMessage());
            return Optional.empty();
        }
    }

    public interface TokenService {
        TokenResponse getToken(String authCode);
    }

    private Optional<APIGatewayProxyResponseEvent> checkForAisIntervention(
            OrchSessionItem orchSession,
            AuditContext auditContext,
            String ipAddress,
            String persistentSessionId,
            String clientSessionId,
            String clientId) {
        AccountIntervention intervention =
                segmentedFunctionCall(
                        "AIS: getAccountIntervention",
                        () ->
                                accountInterventionService.getAccountIntervention(
                                        orchSession.getInternalCommonSubjectId(), auditContext));
        if (configurationService.isAccountInterventionServiceActionEnabled()
                && (intervention.getBlocked() || intervention.getSuspended())) {
            return Optional.of(
                    logoutService.handleAccountInterventionLogout(
                            new DestroySessionsRequest(orchSession.getSessionId(), orchSession),
                            orchSession.getInternalCommonSubjectId(),
                            ipAddress,
                            persistentSessionId,
                            clientSessionId,
                            clientId,
                            intervention));
        }
        return Optional.empty();
    }

    public AuthenticationSuccessResponse generateReturnCodeAuthenticationResponse(
            AuthenticationRequest authRequest,
            OrchSessionItem orchSession,
            OrchClientSessionItem clientSession,
            UserInfo userIdentityUserInfo,
            String ipAddress,
            String persistentSessionId,
            String clientId,
            String email,
            String subjectId) {
        LOG.warn("SPOT will not be invoked due to returnCode. Returning authCode to RP");
        var clientSessionId = clientSession.getClientSessionId();
        var clientName = clientSession.getClientName();
        var rpPairwiseSubject = new Subject(clientSession.getRpPairwiseId());
        var internalPairwiseSubjectId = orchSession.getInternalCommonSubjectId();
        segmentedFunctionCall(
                "saveIdentityClaims",
                () ->
                        saveIdentityClaimsToDynamo(
                                clientSessionId, rpPairwiseSubject, userIdentityUserInfo, null));
        return generateAuthenticationResponse(
                authRequest,
                orchSession,
                clientSessionId,
                ipAddress,
                persistentSessionId,
                clientId,
                clientName,
                email,
                subjectId,
                rpPairwiseSubject.getValue(),
                internalPairwiseSubjectId);
    }

    public AuthenticationSuccessResponse generateAuthenticationResponse(
            AuthenticationRequest authRequest,
            OrchSessionItem orchSession,
            String clientSessionId,
            String ipAddress,
            String persistentSessionId,
            String clientId,
            String clientName,
            String email,
            String subjectId,
            String rpPairwiseSubjectId,
            String internalPairwiseSubjectId) {
        var authCode =
                orchAuthCodeService.generateAndSaveAuthorisationCode(
                        clientId,
                        clientSessionId,
                        email,
                        orchSession.getAuthTime(),
                        internalPairwiseSubjectId);

        var authenticationResponse =
                new AuthenticationSuccessResponse(
                        authRequest.getRedirectionURI(),
                        authCode,
                        null,
                        null,
                        authRequest.getState(),
                        null,
                        authRequest.getResponseMode());
        sendAuditEvent(
                authRequest,
                orchSession,
                clientSessionId,
                ipAddress,
                persistentSessionId,
                email,
                subjectId,
                rpPairwiseSubjectId,
                internalPairwiseSubjectId,
                authCode);
        sendCloudwatchMetrics(orchSession, clientId, clientName);
        authCodeResponseService.saveSession(false, orchSessionService, orchSession);
        return authenticationResponse;
    }

    private void sendAuditEvent(
            AuthenticationRequest authRequest,
            OrchSessionItem orchSession,
            String clientSessionId,
            String ipAddress,
            String persistentSessionId,
            String email,
            String subjectId,
            String rpPairwiseSubjectId,
            String internalPairwiseSubjectId,
            AuthorizationCode authCode) {
        var metadataPairs = new ArrayList<AuditService.MetadataPair>();
        metadataPairs.add(pair("internalSubjectId", subjectId));
        metadataPairs.add(pair("isNewAccount", orchSession.getIsNewAccount()));
        metadataPairs.add(pair("rpPairwiseId", rpPairwiseSubjectId));
        metadataPairs.add(pair("authCode", authCode));
        if (authRequest.getNonce() != null) {
            metadataPairs.add(pair("nonce", authRequest.getNonce().getValue()));
        }

        auditService.submitAuditEvent(
                auditEventConfiguration.authCodeIssued(),
                authRequest.getClientID().getValue(),
                TxmaAuditUser.user()
                        .withGovukSigninJourneyId(clientSessionId)
                        .withSessionId(orchSession.getSessionId())
                        .withUserId(internalPairwiseSubjectId)
                        .withEmail(Optional.ofNullable(email).orElse(AuditService.UNKNOWN))
                        .withIpAddress(ipAddress)
                        .withPersistentSessionId(persistentSessionId),
                metadataPairs.toArray(AuditService.MetadataPair[]::new));
    }

    private void sendCloudwatchMetrics(
            OrchSessionItem orchSession, String clientId, String clientName) {
        var dimensions =
                authCodeResponseService.getDimensions(orchSession, clientName, clientId, false);

        metrics.increment("SignIn", dimensions);

        metrics.incrementSignInByClient(orchSession.getIsNewAccount(), clientId, clientName);
        metrics.increment(
                "orchIdentityJourneyCompleted",
                Map.of(
                        "clientName", clientName,
                        "clientId", clientId));
        metrics.increment("orchJourneyCompleted", Map.of("journeyType", "identity"));
    }

    public void saveIdentityClaimsToDynamo(
            String clientSessionId,
            Subject rpPairwiseSubject,
            UserInfo userIdentityUserInfo,
            Long spotQueuedAt) {
        LOG.info("Checking for additional identity claims to save to dynamo");
        var additionalClaims = new HashMap<String, String>();
        ValidClaims.getAllValidClaims().stream()
                .filter(t -> !t.equals(ValidClaims.CORE_IDENTITY_JWT.getValue()))
                .filter(claim -> Objects.nonNull(userIdentityUserInfo.toJSONObject().get(claim)))
                .forEach(
                        finalClaim ->
                                additionalClaims.put(
                                        finalClaim,
                                        userIdentityUserInfo
                                                .toJSONObject()
                                                .get(finalClaim)
                                                .toString()));
        LOG.info("Additional identity claims present: {}", !additionalClaims.isEmpty());

        var ipvCoreIdentityClaim =
                userIdentityUserInfo.getClaim(IdentityClaims.CORE_IDENTITY.getValue());
        String ipvCoreIdentityString =
                ipvCoreIdentityClaim == null ? "" : ipvCoreIdentityClaim.toString();
        dynamoIdentityService.saveIdentityClaims(
                clientSessionId,
                rpPairwiseSubject.getValue(),
                additionalClaims,
                (String) userIdentityUserInfo.getClaim(VOT.getValue()),
                ipvCoreIdentityString,
                spotQueuedAt);
    }

    public void queueSPOTRequest(
            LogIds logIds,
            String sectorIdentifier,
            UserInfo authUserInfo,
            Subject pairwiseSubject,
            UserInfo userIdentityUserInfo,
            String clientId) {
        LOG.info("Constructing SPOT request ready to queue");
        var spotClaimsBuilder =
                SPOTClaims.builder()
                        .withClaim(VOT.getValue(), userIdentityUserInfo.getClaim(VOT.getValue()))
                        .withClaim(
                                IdentityClaims.CREDENTIAL_JWT.getValue(),
                                userIdentityUserInfo
                                        .toJSONObject()
                                        .get(IdentityClaims.CREDENTIAL_JWT.getValue()))
                        .withClaim(
                                IdentityClaims.CORE_IDENTITY.getValue(),
                                userIdentityUserInfo
                                        .toJSONObject()
                                        .get(IdentityClaims.CORE_IDENTITY.getValue()))
                        .withVtm(oidcAPI.trustmarkURI().toString());

        var spotRequest =
                new SPOTRequest(
                        spotClaimsBuilder.build(),
                        authUserInfo.getStringClaim(AuthUserInfoClaims.LOCAL_ACCOUNT_ID.getValue()),
                        authUserInfo.getStringClaim(AuthUserInfoClaims.SALT.getValue()),
                        sectorIdentifier,
                        pairwiseSubject.getValue(),
                        logIds,
                        clientId);
        var spotRequestString = objectMapper.writeValueAsString(spotRequest);
        if (configurationService.isNewSpotRequestQueueWritingEnabled()) {
            spotSqsClient.send(spotRequestString);
        }
        LOG.info("SPOT request placed on queue");
    }
}

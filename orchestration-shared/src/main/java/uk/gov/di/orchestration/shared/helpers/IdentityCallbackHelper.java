package uk.gov.di.orchestration.shared.helpers;

import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.audit.AuditContext;
import uk.gov.di.orchestration.audit.TxmaAuditUser;
import uk.gov.di.orchestration.shared.api.CommonFrontend;
import uk.gov.di.orchestration.shared.entity.AuthUserInfoClaims;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.IdentityProgressStatus;
import uk.gov.di.orchestration.shared.entity.OrchClientSessionItem;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem;
import uk.gov.di.orchestration.shared.entity.ResponseHeaders;
import uk.gov.di.orchestration.shared.exceptions.IdentityResponseValidationError;
import uk.gov.di.orchestration.shared.services.AccountInterventionService;
import uk.gov.di.orchestration.shared.services.AuditService;
import uk.gov.di.orchestration.shared.services.AuthenticationUserInfoStorageService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.CrossBrowserOrchestrationService;
import uk.gov.di.orchestration.shared.services.DynamoClientService;
import uk.gov.di.orchestration.shared.services.IdentityProgressService;
import uk.gov.di.orchestration.shared.services.LogoutService;
import uk.gov.di.orchestration.shared.services.OrchClientSessionService;
import uk.gov.di.orchestration.shared.services.OrchSessionService;
import uk.gov.di.orchestration.shared.services.RedirectService;

import java.net.URI;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import static uk.gov.di.orchestration.shared.entity.ValidClaims.RETURN_CODE;
import static uk.gov.di.orchestration.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.orchestration.shared.helpers.ClientSubjectHelper.getSectorIdentifierForClient;
import static uk.gov.di.orchestration.shared.helpers.InstrumentationHelper.segmentedFunctionCall;

public class IdentityCallbackHelper {
    private static final Logger LOG = LogManager.getLogger(IdentityCallbackHelper.class);
    private final ConfigurationService configurationService;
    private final OrchSessionService orchSessionService;
    private final AuthenticationUserInfoStorageService authUserInfoStorageService;
    private final OrchClientSessionService orchClientSessionService;
    private final DynamoClientService dynamoClientService;
    private final AuditService auditService;
    private final LogoutService logoutService;
    private final AccountInterventionService accountInterventionService;
    private final CrossBrowserOrchestrationService crossBrowserOrchestrationService;
    private final CommonFrontend frontend;
    private final IdentityProgressService identityProgressService;

    public IdentityCallbackHelper(
            ConfigurationService configurationService,
            OrchSessionService orchSessionService,
            AuthenticationUserInfoStorageService authUserInfoStorageService,
            OrchClientSessionService orchClientSessionService,
            DynamoClientService dynamoClientService,
            AuditService auditService,
            LogoutService logoutService,
            AccountInterventionService accountInterventionService,
            CrossBrowserOrchestrationService crossBrowserOrchestrationService,
            CommonFrontend frontend,
            IdentityProgressService identityProgressService) {
        this.configurationService = configurationService;
        this.orchSessionService = orchSessionService;
        this.authUserInfoStorageService = authUserInfoStorageService;
        this.orchClientSessionService = orchClientSessionService;
        this.dynamoClientService = dynamoClientService;
        this.auditService = auditService;
        this.logoutService = logoutService;
        this.accountInterventionService = accountInterventionService;
        this.crossBrowserOrchestrationService = crossBrowserOrchestrationService;
        this.frontend = frontend;
        this.identityProgressService = identityProgressService;
    }

    public void test(
            OrchSessionItem orchSession,
            OrchClientSessionItem orchClientSession,
            ClientRegistry clientRegistry,
            String persistentId)
            throws Exception {
        var clientSessionId = orchClientSession.getClientSessionId();
        var sessionId = orchSession.getSessionId();
        var clientId = clientRegistry.getClientID();
        UserInfo authUserInfo =
                getAuthUserInfo(
                                authUserInfoStorageService,
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
                IPVAuditableEvent.IPV_AUTHORISATION_RESPONSE_RECEIVED, clientId, user);

        var tokenResponse =
                segmentedFunctionCall(
                        "getIpvToken",
                        () ->
                                ipvTokenService.getToken(
                                        input.getQueryStringParameters().get("code")));
        if (!tokenResponse.indicatesSuccess()) {
            auditService.submitAuditEvent(
                    IPVAuditableEvent.IPV_UNSUCCESSFUL_TOKEN_RESPONSE_RECEIVED, clientId, user);
            return RedirectService.redirectToFrontendErrorPageWithErrorLog(
                    frontend.errorURI(),
                    new Exception(
                            String.format(
                                    "IPV TokenResponse was not successful: %s",
                                    tokenResponse.toErrorResponse().toJSONObject())));
        }
        auditService.submitAuditEvent(
                IPVAuditableEvent.IPV_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED, clientId, user);

        var userIdentityUserInfo =
                ipvTokenService.sendIpvUserIdentityRequest(
                        new UserInfoRequest(
                                ConstructUriHelper.buildURI(
                                        configurationService.getIPVBackendURI().toString(),
                                        "user-identity"),
                                tokenResponse
                                        .toSuccessResponse()
                                        .getTokens()
                                        .getBearerAccessToken()));

        auditService.submitAuditEvent(
                IPVAuditableEvent.IPV_SUCCESSFUL_IDENTITY_RESPONSE_RECEIVED, clientId, user);
        var vtrList = orchClientSession.getVtrList();
        var userIdentityError =
                ipvCallbackHelper.validateUserIdentityResponse(userIdentityUserInfo, vtrList);
        if (userIdentityError.isPresent()) {
            var aisResponseOpt =
                    checkForAisIntervention(orchSession, auditContext, input, clientId);
            if (aisResponseOpt.isPresent()) {
                return aisResponseOpt.get();
            }
            var returnCode = userIdentityUserInfo.getClaim(RETURN_CODE.getValue());
            if (returnCodePresentInIPVResponse(returnCode)) {
                if (rpRequestedReturnCode(clientRegistry, authRequest)) {
                    LOG.info("Generating auth code response for return code(s)");

                    var authenticationResponse =
                            ipvCallbackHelper.generateReturnCodeAuthenticationResponse(
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
        var logIds =
                new LogIds(
                        sessionId,
                        persistentId,
                        context.getAwsRequestId(),
                        clientId,
                        clientSessionId);
        ipvCallbackHelper.queueSPOTRequest(
                logIds,
                getSectorIdentifierForClient(
                        clientRegistry, configurationService.getInternalSectorURI()),
                authUserInfo,
                rpPairwiseSubject,
                userIdentityUserInfo,
                clientId);

        var spotQueuedAt = NowHelper.now().toInstant().toEpochMilli();

        auditService.submitAuditEvent(IPVAuditableEvent.IPV_SPOT_REQUESTED, clientId, user);
        segmentedFunctionCall(
                "saveIdentityClaims",
                () ->
                        ipvCallbackHelper.saveIdentityClaimsToDynamo(
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
                        checkForAisIntervention(orchSession, auditContext, input, clientId);
                if (aisResponseOpt.isPresent()) {
                    return aisResponseOpt.get();
                }
                redirectURI =
                        ipvCallbackHelper
                                .generateAuthenticationResponse(
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
    }

    private static Optional<UserInfo> getAuthUserInfo(
            AuthenticationUserInfoStorageService authUserInfoStorageService,
            String internalCommonSubjectId,
            String clientSessionId) {

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

    public Optional<IdentityResponseValidationError> validateResponse(
            Map<String, String> queryParams, Optional<String> stateFromDynamo) {
        if (queryParams == null || queryParams.isEmpty()) {
            LOG.warn("No Query parameters in Authorisation response");
            return Optional.of(
                    new IdentityResponseValidationError(
                            OAuth2Error.INVALID_REQUEST_CODE, "No query parameters present"));
        }
        if (!queryParams.containsKey("state") || queryParams.get("state").isEmpty()) {
            LOG.warn("No state param in Authorisation response");
            return Optional.of(
                    new IdentityResponseValidationError(
                            OAuth2Error.INVALID_REQUEST_CODE,
                            "No state param present in Authorisation response"));
        }
        if (!isStateValid(stateFromDynamo, queryParams.get("state"))) {
            return Optional.of(
                    new IdentityResponseValidationError(
                            OAuth2Error.INVALID_REQUEST_CODE,
                            "Invalid state param present in Authorisation response"));
        }
        if (!queryParams.containsKey("code") || queryParams.get("code").isEmpty()) {
            LOG.warn("No code param in Authorisation response");
            return Optional.of(
                    new IdentityResponseValidationError(
                            OAuth2Error.INVALID_REQUEST_CODE,
                            "No code param present in Authorisation response"));
        }
        return Optional.empty();
    }

    private boolean isStateValid(Optional<String> stateFromDynamo, String responseState) {
        if (stateFromDynamo.isEmpty()) {
            LOG.info("No state found in Dynamo");
            return false;
        }

        State storedState = new State(stateFromDynamo.get());
        LOG.info(
                "Response state: {} and Stored state: {}. Are equal: {}",
                responseState,
                storedState.getValue(),
                responseState.equals(storedState.getValue()));
        return responseState.equals(storedState.getValue());
    }
}

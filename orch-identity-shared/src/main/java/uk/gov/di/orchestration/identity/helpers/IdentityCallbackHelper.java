package uk.gov.di.orchestration.identity.helpers;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.audit.AuditContext;
import uk.gov.di.orchestration.audit.TxmaAuditUser;
import uk.gov.di.orchestration.identity.entity.IdentityProgressStatus;
import uk.gov.di.orchestration.identity.exceptions.IdentityResponseValidationError;
import uk.gov.di.orchestration.identity.services.IdentityProgressService;
import uk.gov.di.orchestration.shared.api.CommonFrontend;
import uk.gov.di.orchestration.shared.api.OidcAPI;
import uk.gov.di.orchestration.shared.entity.AuthUserInfoClaims;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.OrchClientSessionItem;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem;
import uk.gov.di.orchestration.shared.entity.ResponseHeaders;
import uk.gov.di.orchestration.shared.entity.VectorOfTrust;
import uk.gov.di.orchestration.shared.exceptions.IdentityCallbackException;
import uk.gov.di.orchestration.shared.exceptions.UnsuccessfulCredentialResponseException;
import uk.gov.di.orchestration.shared.helpers.ConstructUriHelper;
import uk.gov.di.orchestration.shared.helpers.NowHelper;
import uk.gov.di.orchestration.shared.services.AuditService;
import uk.gov.di.orchestration.shared.services.AuthenticationUserInfoStorageService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.RedirectService;

import java.io.IOException;
import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import static java.lang.String.format;
import static uk.gov.di.orchestration.shared.entity.IdentityClaims.VOT;
import static uk.gov.di.orchestration.shared.entity.IdentityClaims.VTM;
import static uk.gov.di.orchestration.shared.entity.ValidClaims.RETURN_CODE;
import static uk.gov.di.orchestration.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.orchestration.shared.helpers.ClientSubjectHelper.getSectorIdentifierForClient;
import static uk.gov.di.orchestration.shared.helpers.InstrumentationHelper.segmentedFunctionCall;

public class IdentityCallbackHelper {
    private static final Logger LOG = LogManager.getLogger(IdentityCallbackHelper.class);
    private final ConfigurationService configurationService;
    private final AuthenticationUserInfoStorageService authUserInfoStorageService;
    private final AuditService auditService;
    private final CommonFrontend frontend;
    private final IdentityProgressService identityProgressService;
    private final TokenService tokenService;
    private final OidcAPI oidcAPI;

    public IdentityCallbackHelper(
            ConfigurationService configurationService,
            AuthenticationUserInfoStorageService authUserInfoStorageService,
            AuditService auditService,
            CommonFrontend frontend,
            IdentityProgressService identityProgressService,
            TokenService tokenService,
            OidcAPI oidcAPI) {
        this.configurationService = configurationService;
        this.authUserInfoStorageService = authUserInfoStorageService;
        this.auditService = auditService;
        this.frontend = frontend;
        this.identityProgressService = identityProgressService;
        this.tokenService = tokenService;
        this.oidcAPI = oidcAPI;
    }

    public APIGatewayProxyResponseEvent test(
            OrchSessionItem orchSession,
            OrchClientSessionItem orchClientSession,
            ClientRegistry clientRegistry,
            String persistentId,
            String ipAddress,
            String authCode,
            AuthenticationRequest authRequest)
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

        //        auditService.submitAuditEvent(
        //                IPVAuditableEvent.IPV_AUTHORISATION_RESPONSE_RECEIVED, clientId, user);

        var tokenResponse =
                segmentedFunctionCall("getIpvToken", () -> tokenService.getToken(authCode));
        if (!tokenResponse.indicatesSuccess()) {
            //            auditService.submitAuditEvent(
            //                    IPVAuditableEvent.IPV_UNSUCCESSFUL_TOKEN_RESPONSE_RECEIVED,
            // clientId, user);
            return RedirectService.redirectToFrontendErrorPageWithErrorLog(
                    frontend.errorURI(),
                    new Exception(
                            String.format(
                                    "IPV TokenResponse was not successful: %s",
                                    tokenResponse.toErrorResponse().toJSONObject())));
        }
        //        auditService.submitAuditEvent(
        //                IPVAuditableEvent.IPV_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED, clientId, user);

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

        //        auditService.submitAuditEvent(
        //                IPVAuditableEvent.IPV_SUCCESSFUL_IDENTITY_RESPONSE_RECEIVED, clientId,
        // user);
        var vtrList = orchClientSession.getVtrList();
        var userIdentityError = validateUserIdentityResponse(userIdentityUserInfo, vtrList);
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
        return null;
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

    public interface TokenService {
        TokenResponse getToken(String authCode);
    }

    public UserInfo sendUserIdentityRequest(UserInfoRequest userInfoRequest)
            throws UnsuccessfulCredentialResponseException {
        try {
            LOG.info("Sending IPV userinfo request");
            int count = 0;
            int maxTries = 2;
            UserInfoResponse userIdentityResponse;
            do {
                if (count > 0) LOG.warn("Retrying IPV user identity request");
                count++;
                var httpResponse = userInfoRequest.toHTTPRequest().send();
                userIdentityResponse = UserInfoResponse.parse(httpResponse);
                if (!httpResponse.indicatesSuccess()) {
                    LOG.warn(
                            format(
                                    "Unsuccessful %s response from IPV user identity endpoint on attempt %d: %s ",
                                    httpResponse.getStatusCode(), count, httpResponse.getBody()));
                }
            } while (!userIdentityResponse.indicatesSuccess() && count < maxTries);

            if (!userIdentityResponse.indicatesSuccess()) {
                LOG.error("Response from user-identity does not indicate success");
                throw new UnsuccessfulCredentialResponseException(
                        userIdentityResponse.toErrorResponse().toString());
            } else {
                return userIdentityResponse.toSuccessResponse().getUserInfo();
            }
        } catch (ParseException e) {
            LOG.error("Error when attempting to parse HTTPResponse to UserInfoResponse");
            throw new UnsuccessfulCredentialResponseException(
                    "Error when attempting to parse http response to UserInfoResponse");
        } catch (IOException e) {
            LOG.error("Error when attempting to call IPV user-identity endpoint", e);
            throw new RuntimeException(e);
        }
    }

    public Optional<ErrorObject> validateUserIdentityResponse(
            UserInfo userIdentityUserInfo, List<VectorOfTrust> vtrList)
            throws IdentityCallbackException {
        LOG.info("Validating userinfo response");
        for (VectorOfTrust vtr : vtrList) {
            if (vtr.getLevelOfConfidence()
                    .getValue()
                    .equals(userIdentityUserInfo.getClaim(VOT.getValue()))) {
                var trustmarkURL = oidcAPI.trustmarkURI().toString();

                if (!trustmarkURL.equals(userIdentityUserInfo.getClaim(VTM.getValue()))) {
                    LOG.warn("VTM does not contain expected trustmark URL");
                    throw new IdentityCallbackException("IPV trustmark is invalid");
                }
                return Optional.empty();
            }
        }
        LOG.warn("IPV missing vot or vot not in vtr list.");
        return Optional.of(OAuth2Error.ACCESS_DENIED);
    }
}

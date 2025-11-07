package uk.gov.di.authentication.ipv.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.authentication.ipv.domain.IPVAuditableEvent;
import uk.gov.di.authentication.ipv.entity.IPVCallbackNoSessionException;
import uk.gov.di.authentication.ipv.entity.IpvCallbackException;
import uk.gov.di.authentication.ipv.entity.LogIds;
import uk.gov.di.authentication.ipv.helpers.IPVCallbackHelper;
import uk.gov.di.authentication.ipv.services.IPVAuthorisationService;
import uk.gov.di.authentication.ipv.services.IPVTokenService;
import uk.gov.di.orchestration.audit.AuditContext;
import uk.gov.di.orchestration.audit.TxmaAuditUser;
import uk.gov.di.orchestration.shared.api.AuthFrontend;
import uk.gov.di.orchestration.shared.api.CommonFrontend;
import uk.gov.di.orchestration.shared.entity.AccountIntervention;
import uk.gov.di.orchestration.shared.entity.AuthUserInfoClaims;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.DestroySessionsRequest;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem;
import uk.gov.di.orchestration.shared.entity.ResponseHeaders;
import uk.gov.di.orchestration.shared.exceptions.NoSessionException;
import uk.gov.di.orchestration.shared.exceptions.OrchAuthCodeException;
import uk.gov.di.orchestration.shared.exceptions.UnsuccessfulCredentialResponseException;
import uk.gov.di.orchestration.shared.helpers.ConstructUriHelper;
import uk.gov.di.orchestration.shared.helpers.CookieHelper;
import uk.gov.di.orchestration.shared.helpers.IpAddressHelper;
import uk.gov.di.orchestration.shared.helpers.PersistentIdHelper;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.serialization.Json.JsonException;
import uk.gov.di.orchestration.shared.services.AccountInterventionService;
import uk.gov.di.orchestration.shared.services.AuditService;
import uk.gov.di.orchestration.shared.services.AuthenticationUserInfoStorageService;
import uk.gov.di.orchestration.shared.services.CloudwatchMetricsService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.CrossBrowserOrchestrationService;
import uk.gov.di.orchestration.shared.services.DynamoClientService;
import uk.gov.di.orchestration.shared.services.KmsConnectionService;
import uk.gov.di.orchestration.shared.services.LogoutService;
import uk.gov.di.orchestration.shared.services.OrchClientSessionService;
import uk.gov.di.orchestration.shared.services.OrchSessionService;
import uk.gov.di.orchestration.shared.services.RedirectService;
import uk.gov.di.orchestration.shared.services.SerializationService;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import static com.nimbusds.oauth2.sdk.OAuth2Error.ACCESS_DENIED_CODE;
import static uk.gov.di.orchestration.shared.entity.ValidClaims.RETURN_CODE;
import static uk.gov.di.orchestration.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.orchestration.shared.helpers.AuditHelper.attachTxmaAuditFieldFromHeaders;
import static uk.gov.di.orchestration.shared.helpers.ClientSubjectHelper.getSectorIdentifierForClient;
import static uk.gov.di.orchestration.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.CLIENT_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.CLIENT_SESSION_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.GOVUK_SIGNIN_JOURNEY_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.PERSISTENT_SESSION_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachSessionIdToLogs;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachTraceId;

public class IPVCallbackHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(IPVCallbackHandler.class);
    private final ConfigurationService configurationService;
    private final IPVAuthorisationService ipvAuthorisationService;
    private final IPVTokenService ipvTokenService;
    private final OrchSessionService orchSessionService;
    private final AuthenticationUserInfoStorageService authUserInfoStorageService;
    private final OrchClientSessionService orchClientSessionService;
    private final DynamoClientService dynamoClientService;
    private final AuditService auditService;
    private final LogoutService logoutService;
    private final AccountInterventionService accountInterventionService;
    private final IPVCallbackHelper ipvCallbackHelper;
    private final CrossBrowserOrchestrationService crossBrowserOrchestrationService;
    private final CommonFrontend frontend;
    protected final Json objectMapper = SerializationService.getInstance();

    public IPVCallbackHandler() {
        this(ConfigurationService.getInstance());
    }

    public IPVCallbackHandler(
            ConfigurationService configurationService,
            IPVAuthorisationService responseService,
            IPVTokenService ipvTokenService,
            OrchSessionService orchSessionService,
            AuthenticationUserInfoStorageService authUserInfoStorageService,
            OrchClientSessionService orchClientSessionService,
            DynamoClientService dynamoClientService,
            AuditService auditService,
            LogoutService logoutService,
            AccountInterventionService accountInterventionService,
            CrossBrowserOrchestrationService crossBrowserOrchestrationService,
            IPVCallbackHelper ipvCallbackHelper,
            CommonFrontend frontend) {
        this.configurationService = configurationService;
        this.ipvAuthorisationService = responseService;
        this.ipvTokenService = ipvTokenService;
        this.orchSessionService = orchSessionService;
        this.authUserInfoStorageService = authUserInfoStorageService;
        this.orchClientSessionService = orchClientSessionService;
        this.dynamoClientService = dynamoClientService;
        this.auditService = auditService;
        this.logoutService = logoutService;
        this.accountInterventionService = accountInterventionService;
        this.crossBrowserOrchestrationService = crossBrowserOrchestrationService;
        this.ipvCallbackHelper = ipvCallbackHelper;
        this.frontend = frontend;
    }

    public IPVCallbackHandler(ConfigurationService configurationService) {
        var kmsConnectionService = new KmsConnectionService(configurationService);
        this.configurationService = configurationService;
        this.ipvAuthorisationService =
                new IPVAuthorisationService(configurationService, kmsConnectionService);
        this.ipvTokenService = new IPVTokenService(configurationService, kmsConnectionService);
        this.orchSessionService = new OrchSessionService(configurationService);
        this.authUserInfoStorageService =
                new AuthenticationUserInfoStorageService(configurationService);
        this.orchClientSessionService = new OrchClientSessionService(configurationService);
        this.dynamoClientService = new DynamoClientService(configurationService);
        this.auditService = new AuditService(configurationService);
        this.logoutService = new LogoutService(configurationService);
        this.accountInterventionService =
                new AccountInterventionService(
                        configurationService,
                        new CloudwatchMetricsService(configurationService),
                        auditService);
        this.crossBrowserOrchestrationService =
                new CrossBrowserOrchestrationService(configurationService);
        this.ipvCallbackHelper = new IPVCallbackHelper(configurationService);
        this.frontend = new AuthFrontend(configurationService);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        ThreadContext.clearMap();
        attachTraceId();
        LOG.info("Request received to IPVCallbackHandler");
        attachTxmaAuditFieldFromHeaders(input.getHeaders());
        try {
            if (!configurationService.isIdentityEnabled()) {
                throw new IpvCallbackException("Identity is not enabled");
            }
            var sessionCookiesIds =
                    CookieHelper.parseSessionCookie(input.getHeaders()).orElse(null);
            if (Objects.isNull(sessionCookiesIds)) {
                var noSessionEntity =
                        crossBrowserOrchestrationService.generateNoSessionOrchestrationEntity(
                                input.getQueryStringParameters());
                var authRequest =
                        AuthenticationRequest.parse(
                                noSessionEntity.getClientSession().getAuthRequestParams());
                attachLogFieldToLogs(CLIENT_ID, authRequest.getClientID().getValue());
                return ipvCallbackHelper.generateAuthenticationErrorResponse(
                        authRequest,
                        noSessionEntity.getErrorObject(),
                        true,
                        noSessionEntity.getClientSessionId(),
                        AuditService.UNKNOWN);
            }
            var sessionId = sessionCookiesIds.getSessionId();
            OrchSessionItem orchSession =
                    orchSessionService
                            .getSession(sessionId)
                            .orElseThrow(
                                    () ->
                                            new IPVCallbackNoSessionException(
                                                    "Orchestration session not found in DynamoDB"));

            attachSessionIdToLogs(sessionId);
            var persistentId =
                    PersistentIdHelper.extractPersistentIdFromCookieHeader(input.getHeaders());
            attachLogFieldToLogs(PERSISTENT_SESSION_ID, persistentId);
            var clientSessionId = sessionCookiesIds.getClientSessionId();
            attachLogFieldToLogs(CLIENT_SESSION_ID, clientSessionId);
            attachLogFieldToLogs(GOVUK_SIGNIN_JOURNEY_ID, clientSessionId);
            var orchClientSession =
                    orchClientSessionService
                            .getClientSession(clientSessionId)
                            .orElseThrow(
                                    () ->
                                            new IPVCallbackNoSessionException(
                                                    "ClientSession not found"));

            var mismatchedEntity =
                    crossBrowserOrchestrationService.generateEntityForMismatchInClientSessionId(
                            input.getQueryStringParameters(), clientSessionId, orchSession);

            if (mismatchedEntity.isPresent()) {

                var authRequestFromStateDerivedRP =
                        AuthenticationRequest.parse(
                                mismatchedEntity.get().getClientSession().getAuthRequestParams());
                attachLogFieldToLogs(
                        CLIENT_ID, authRequestFromStateDerivedRP.getClientID().getValue());

                return ipvCallbackHelper.generateAuthenticationErrorResponse(
                        authRequestFromStateDerivedRP,
                        mismatchedEntity.get().getErrorObject(),
                        false,
                        mismatchedEntity.get().getClientSessionId(),
                        AuditService.UNKNOWN);
            }

            var authRequest = AuthenticationRequest.parse(orchClientSession.getAuthRequestParams());
            var clientId = authRequest.getClientID().getValue();
            attachLogFieldToLogs(CLIENT_ID, clientId);
            var clientRegistry =
                    dynamoClientService
                            .getClient(clientId)
                            .orElseThrow(
                                    () ->
                                            new IpvCallbackException(
                                                    "Client registry not found with given clientId"));

            var errorObject =
                    segmentedFunctionCall(
                            () ->
                                    ipvAuthorisationService.validateResponse(
                                            input.getQueryStringParameters(), sessionId));

            var ipAddress = IpAddressHelper.extractIpAddress(input);

            if (errorObject.isPresent()) {
                var destroySessionRequest = new DestroySessionsRequest(sessionId, orchSession);
                AccountIntervention intervention =
                        segmentedFunctionCall(
                                () ->
                                        this.accountInterventionService.getAccountIntervention(
                                                orchSession.getInternalCommonSubjectId(),
                                                new AuditContext(
                                                        clientSessionId,
                                                        sessionId,
                                                        clientId,
                                                        orchSession.getInternalCommonSubjectId(),
                                                        AuditService.UNKNOWN,
                                                        ipAddress,
                                                        AuditService.UNKNOWN,
                                                        persistentId)));
                if (configurationService.isAccountInterventionServiceActionEnabled()
                        && (intervention.getBlocked() || intervention.getSuspended())) {
                    return logoutService.handleAccountInterventionLogout(
                            destroySessionRequest,
                            orchSession.getInternalCommonSubjectId(),
                            input,
                            clientId,
                            intervention);
                }

                if (errorObject.get().isSessionInvalidation()) {
                    return logoutService.handleSessionInvalidationLogout(
                            destroySessionRequest,
                            orchSession.getInternalCommonSubjectId(),
                            input,
                            clientId);
                }

                return ipvCallbackHelper.generateAuthenticationErrorResponse(
                        authRequest,
                        new ErrorObject(ACCESS_DENIED_CODE, errorObject.get().errorDescription()),
                        false,
                        clientSessionId,
                        sessionId);
            }

            UserInfo authUserInfo =
                    getAuthUserInfo(
                                    authUserInfoStorageService,
                                    orchSession.getInternalCommonSubjectId(),
                                    clientSessionId)
                            .orElseThrow(() -> new IpvCallbackException("authUserInfo not found"));

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
                            () ->
                                    ipvTokenService.getToken(
                                            input.getQueryStringParameters().get("code")));
            if (!tokenResponse.indicatesSuccess()) {
                auditService.submitAuditEvent(
                        IPVAuditableEvent.IPV_UNSUCCESSFUL_TOKEN_RESPONSE_RECEIVED, clientId, user);
                return RedirectService.redirectToFrontendErrorPage(
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
                AccountIntervention intervention =
                        segmentedFunctionCall(
                                () ->
                                        this.accountInterventionService.getAccountIntervention(
                                                orchSession.getInternalCommonSubjectId(),
                                                auditContext));
                if (configurationService.isAccountInterventionServiceActionEnabled()
                        && (intervention.getBlocked() || intervention.getSuspended())) {
                    return logoutService.handleAccountInterventionLogout(
                            new DestroySessionsRequest(sessionId, orchSession),
                            orchSession.getInternalCommonSubjectId(),
                            input,
                            clientId,
                            intervention);
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

            auditService.submitAuditEvent(IPVAuditableEvent.IPV_SPOT_REQUESTED, clientId, user);
            segmentedFunctionCall(
                    () ->
                            ipvCallbackHelper.saveIdentityClaimsToDynamo(
                                    clientSessionId, rpPairwiseSubject, userIdentityUserInfo));
            var redirectURI = frontend.ipvCallbackURI();
            LOG.info("Successful IPV callback. Redirecting to frontend");
            return generateApiGatewayProxyResponse(
                    302, "", Map.of(ResponseHeaders.LOCATION, redirectURI.toString()), null);
        } catch (NoSessionException e) {
            return RedirectService.redirectToFrontendErrorPageForNoSession(
                    frontend.errorIpvCallbackURI(), e);
        } catch (IpvCallbackException | UnsuccessfulCredentialResponseException e) {
            return RedirectService.redirectToFrontendErrorPage(frontend.errorURI(), e);
        } catch (ParseException e) {
            return RedirectService.redirectToFrontendErrorPage(
                    frontend.errorURI(),
                    new Error("Cannot retrieve auth request params from client session id"));
        } catch (JsonException e) {
            return RedirectService.redirectToFrontendErrorPage(
                    frontend.errorURI(),
                    new Error("Unable to serialize SPOTRequest when placing on queue"));
        } catch (OrchAuthCodeException e) {
            return RedirectService.redirectToFrontendErrorPage(
                    frontend.errorURI(),
                    new Error(
                            String.format(
                                    "Failed to generate and save authorisation code to orch auth code DynamoDB store. Error: %s",
                                    e.getMessage())));
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

    private static boolean returnCodePresentInIPVResponse(Object returnCode) {
        return returnCode instanceof List<?> returnCodeList && !returnCodeList.isEmpty();
    }

    private boolean rpRequestedReturnCode(
            ClientRegistry clientRegistry, AuthenticationRequest authRequest) {
        if (authRequest.getOIDCClaims() == null
                || authRequest.getOIDCClaims().getUserInfoClaimsRequest() == null) {
            return false;
        }
        return clientRegistry.getClaims().contains(RETURN_CODE.getValue())
                && authRequest
                                .getOIDCClaims()
                                .getUserInfoClaimsRequest()
                                .get(RETURN_CODE.getValue())
                        != null;
    }
}

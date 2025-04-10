package uk.gov.di.authentication.ipv.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
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
import uk.gov.di.orchestration.shared.api.OrchFrontend;
import uk.gov.di.orchestration.shared.entity.AccountIntervention;
import uk.gov.di.orchestration.shared.entity.AuthUserInfoClaims;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.DestroySessionsRequest;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem;
import uk.gov.di.orchestration.shared.entity.ResponseHeaders;
import uk.gov.di.orchestration.shared.exceptions.NoSessionException;
import uk.gov.di.orchestration.shared.exceptions.UnsuccessfulCredentialResponseException;
import uk.gov.di.orchestration.shared.exceptions.UserNotFoundException;
import uk.gov.di.orchestration.shared.helpers.ClientSubjectHelper;
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
import uk.gov.di.orchestration.shared.services.DynamoClientService;
import uk.gov.di.orchestration.shared.services.DynamoService;
import uk.gov.di.orchestration.shared.services.KmsConnectionService;
import uk.gov.di.orchestration.shared.services.LogoutService;
import uk.gov.di.orchestration.shared.services.NoSessionOrchestrationService;
import uk.gov.di.orchestration.shared.services.OrchClientSessionService;
import uk.gov.di.orchestration.shared.services.OrchSessionService;
import uk.gov.di.orchestration.shared.services.RedirectService;
import uk.gov.di.orchestration.shared.services.RedisConnectionService;
import uk.gov.di.orchestration.shared.services.SerializationService;
import uk.gov.di.orchestration.shared.services.SessionService;

import java.net.URI;
import java.nio.ByteBuffer;
import java.util.Base64;
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

public class IPVCallbackHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(IPVCallbackHandler.class);
    private final ConfigurationService configurationService;
    private final IPVAuthorisationService ipvAuthorisationService;
    private final IPVTokenService ipvTokenService;
    private final SessionService sessionService;
    private final OrchSessionService orchSessionService;
    private final AuthenticationUserInfoStorageService authUserInfoStorageService;
    private final DynamoService dynamoService;
    private final OrchClientSessionService orchClientSessionService;
    private final DynamoClientService dynamoClientService;
    private final AuditService auditService;
    private final LogoutService logoutService;
    private final AccountInterventionService accountInterventionService;
    private final IPVCallbackHelper ipvCallbackHelper;
    private final NoSessionOrchestrationService noSessionOrchestrationService;
    private final CommonFrontend frontend;
    protected final Json objectMapper = SerializationService.getInstance();

    public IPVCallbackHandler() {
        this(ConfigurationService.getInstance());
    }

    public IPVCallbackHandler(
            ConfigurationService configurationService,
            IPVAuthorisationService responseService,
            IPVTokenService ipvTokenService,
            SessionService sessionService,
            OrchSessionService orchSessionService,
            AuthenticationUserInfoStorageService authUserInfoStorageService,
            DynamoService dynamoService,
            OrchClientSessionService orchClientSessionService,
            DynamoClientService dynamoClientService,
            AuditService auditService,
            LogoutService logoutService,
            AccountInterventionService accountInterventionService,
            NoSessionOrchestrationService noSessionOrchestrationService,
            IPVCallbackHelper ipvCallbackHelper,
            CommonFrontend frontend) {
        this.configurationService = configurationService;
        this.ipvAuthorisationService = responseService;
        this.ipvTokenService = ipvTokenService;
        this.sessionService = sessionService;
        this.orchSessionService = orchSessionService;
        this.authUserInfoStorageService = authUserInfoStorageService;
        this.dynamoService = dynamoService;
        this.orchClientSessionService = orchClientSessionService;
        this.dynamoClientService = dynamoClientService;
        this.auditService = auditService;
        this.logoutService = logoutService;
        this.accountInterventionService = accountInterventionService;
        this.noSessionOrchestrationService = noSessionOrchestrationService;
        this.ipvCallbackHelper = ipvCallbackHelper;
        this.frontend = frontend;
    }

    public IPVCallbackHandler(ConfigurationService configurationService) {
        var kmsConnectionService = new KmsConnectionService(configurationService);
        this.configurationService = configurationService;
        this.ipvAuthorisationService =
                new IPVAuthorisationService(
                        configurationService,
                        new RedisConnectionService(configurationService),
                        kmsConnectionService);
        this.ipvTokenService = new IPVTokenService(configurationService, kmsConnectionService);
        this.sessionService = new SessionService(configurationService);
        this.orchSessionService = new OrchSessionService(configurationService);
        this.authUserInfoStorageService =
                new AuthenticationUserInfoStorageService(configurationService);
        this.dynamoService = new DynamoService(configurationService);
        this.orchClientSessionService = new OrchClientSessionService(configurationService);
        this.dynamoClientService = new DynamoClientService(configurationService);
        this.auditService = new AuditService(configurationService);
        this.logoutService = new LogoutService(configurationService);
        this.accountInterventionService =
                new AccountInterventionService(
                        configurationService,
                        new CloudwatchMetricsService(configurationService),
                        auditService);
        this.noSessionOrchestrationService =
                new NoSessionOrchestrationService(configurationService);
        this.ipvCallbackHelper = new IPVCallbackHelper(configurationService);
        this.frontend = getFrontend(configurationService);
    }

    public IPVCallbackHandler(
            ConfigurationService configurationService, RedisConnectionService redis) {
        var kmsConnectionService = new KmsConnectionService(configurationService);
        this.configurationService = configurationService;
        this.ipvAuthorisationService =
                new IPVAuthorisationService(configurationService, redis, kmsConnectionService);
        this.ipvTokenService = new IPVTokenService(configurationService, kmsConnectionService);
        this.sessionService = new SessionService(configurationService, redis);
        this.orchSessionService = new OrchSessionService(configurationService);
        this.authUserInfoStorageService =
                new AuthenticationUserInfoStorageService(configurationService);
        this.dynamoService = new DynamoService(configurationService);
        this.orchClientSessionService = new OrchClientSessionService(configurationService);
        this.dynamoClientService = new DynamoClientService(configurationService);
        this.auditService = new AuditService(configurationService);
        this.logoutService = new LogoutService(configurationService, redis);
        this.accountInterventionService =
                new AccountInterventionService(
                        configurationService,
                        new CloudwatchMetricsService(configurationService),
                        auditService);
        this.noSessionOrchestrationService =
                new NoSessionOrchestrationService(configurationService, redis);
        this.ipvCallbackHelper = new IPVCallbackHelper(configurationService, redis);
        this.frontend = getFrontend(configurationService);
    }

    public static CommonFrontend getFrontend(ConfigurationService configurationService) {
        return configurationService.getOrchFrontendEnabled()
                ? new OrchFrontend(configurationService)
                : new AuthFrontend(configurationService);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        ThreadContext.clearMap();
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
                        noSessionOrchestrationService.generateNoSessionOrchestrationEntity(
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
            var session =
                    sessionService
                            .getSession(sessionId)
                            .orElseThrow(
                                    () -> new IPVCallbackNoSessionException("Session not found"));
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
                            "validateIpvAuthResponse",
                            () ->
                                    ipvAuthorisationService.validateResponse(
                                            input.getQueryStringParameters(), sessionId));
            var userProfile =
                    dynamoService
                            .getUserProfileByEmailMaybe(session.getEmailAddress())
                            .orElseThrow(
                                    () ->
                                            new IpvCallbackException(
                                                    "Email from session does not have a user profile"));
            var rpPairwiseSubject =
                    ClientSubjectHelper.getSubject(
                            userProfile,
                            clientRegistry,
                            dynamoService,
                            configurationService.getInternalSectorURI());

            var internalPairwiseSubjectId =
                    ClientSubjectHelper.calculatePairwiseIdentifier(
                            userProfile.getSubjectID(),
                            URI.create(configurationService.getInternalSectorURI()),
                            dynamoService.getOrGenerateSalt(userProfile));

            var ipAddress = IpAddressHelper.extractIpAddress(input);
            var user =
                    TxmaAuditUser.user()
                            .withGovukSigninJourneyId(clientSessionId)
                            .withSessionId(sessionId)
                            .withUserId(internalPairwiseSubjectId)
                            .withEmail(session.getEmailAddress())
                            .withPhone(userProfile.getPhoneNumber())
                            .withPersistentSessionId(persistentId);

            var auditContext =
                    new AuditContext(
                            clientSessionId,
                            sessionId,
                            clientId,
                            internalPairwiseSubjectId,
                            session.getEmailAddress(),
                            ipAddress,
                            Objects.isNull(userProfile.getPhoneNumber())
                                    ? AuditService.UNKNOWN
                                    : userProfile.getPhoneNumber(),
                            persistentId);

            if (errorObject.isPresent()) {
                AccountIntervention intervention =
                        segmentedFunctionCall(
                                "AIS: getAccountIntervention",
                                () ->
                                        this.accountInterventionService.getAccountIntervention(
                                                internalPairwiseSubjectId, auditContext));
                if (configurationService.isAccountInterventionServiceActionEnabled()
                        && (intervention.getBlocked() || intervention.getSuspended())) {
                    return logoutService.handleAccountInterventionLogout(
                            new DestroySessionsRequest(sessionId, session),
                            orchSession.getInternalCommonSubjectId(),
                            input,
                            clientId,
                            intervention);
                }

                return ipvCallbackHelper.generateAuthenticationErrorResponse(
                        authRequest,
                        new ErrorObject(ACCESS_DENIED_CODE, errorObject.get().getDescription()),
                        false,
                        clientSessionId,
                        sessionId);
            }

            auditService.submitAuditEvent(
                    IPVAuditableEvent.IPV_AUTHORISATION_RESPONSE_RECEIVED, clientId, user);

            // TODO: ATO-1117: temporary logs to check values are as expected
            LOG.info(
                    "is rpPairwiseId the same on clientSession as calculated: {}",
                    Objects.equals(
                            rpPairwiseSubject.getValue(), orchClientSession.getRpPairwiseId()));
            LOG.info(
                    "is correct pairwiseId for client the same on clientSession as calculated: {}",
                    Objects.equals(
                            rpPairwiseSubject.getValue(),
                            orchClientSession.getCorrectPairwiseIdGivenSubjectType(
                                    clientRegistry.getSubjectType())));
            if (orchSession.getInternalCommonSubjectId() != null
                    && !orchSession.getInternalCommonSubjectId().isBlank()) {
                Optional<UserInfo> authUserInfo =
                        getAuthUserInfo(
                                authUserInfoStorageService,
                                orchSession.getInternalCommonSubjectId(),
                                clientSessionId);

                if (authUserInfo.isEmpty()) {
                    LOG.info("authUserInfo not found");
                } else {
                    LOG.info(
                            "is email the same on authUserInfo as on session: {}",
                            Objects.equals(
                                    session.getEmailAddress(),
                                    authUserInfo.get().getEmailAddress()));
                    if (userProfile.getPhoneNumber() != null) {
                        LOG.info(
                                "is phone number the same on authUserInfo as on UserProfile: {}",
                                Objects.equals(
                                        userProfile.getPhoneNumber(),
                                        authUserInfo.get().getPhoneNumber()));
                    }
                    var saltFromAuthUserInfo = authUserInfo.get().getStringClaim("salt");
                    if (saltFromAuthUserInfo != null && !saltFromAuthUserInfo.isBlank()) {
                        var saltDecoded = Base64.getDecoder().decode(saltFromAuthUserInfo);
                        var saltBuffer = ByteBuffer.wrap(saltDecoded).asReadOnlyBuffer();
                        LOG.info(
                                "is salt the same on authUserInfo as on UserProfile: {}",
                                Objects.equals(userProfile.getSalt(), saltBuffer));
                    } else {
                        LOG.info(
                                "salt on authUserInfo is null or blank. Is salt on UserProfile defined: {}",
                                userProfile.getSalt() != null);
                    }
                    LOG.info(
                            "is subjectId the same on authUserInfo as on UserProfile: {}",
                            Objects.equals(
                                    userProfile.getSubjectID(),
                                    authUserInfo
                                            .get()
                                            .getClaim(
                                                    AuthUserInfoClaims.LOCAL_ACCOUNT_ID
                                                            .getValue())));
                }
            } else {
                LOG.info("internalCommonSubjectId is empty");
            }
            //

            var tokenResponse =
                    segmentedFunctionCall(
                            "getIpvToken",
                            () ->
                                    ipvTokenService.getToken(
                                            input.getQueryStringParameters().get("code")));
            if (!tokenResponse.indicatesSuccess()) {
                LOG.error(
                        "IPV TokenResponse was not successful: {}",
                        tokenResponse.toErrorResponse().toJSONObject());
                auditService.submitAuditEvent(
                        IPVAuditableEvent.IPV_UNSUCCESSFUL_TOKEN_RESPONSE_RECEIVED, clientId, user);
                return RedirectService.redirectToFrontendErrorPage(frontend.errorURI());
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
                                "AIS: getAccountIntervention",
                                () ->
                                        this.accountInterventionService.getAccountIntervention(
                                                internalPairwiseSubjectId, auditContext));
                if (configurationService.isAccountInterventionServiceActionEnabled()
                        && (intervention.getBlocked() || intervention.getSuspended())) {
                    return logoutService.handleAccountInterventionLogout(
                            new DestroySessionsRequest(sessionId, session),
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
                                        clientSessionId,
                                        userProfile,
                                        session,
                                        sessionId,
                                        orchSession,
                                        orchClientSession.getClientName(),
                                        rpPairwiseSubject,
                                        internalPairwiseSubjectId,
                                        userIdentityUserInfo,
                                        ipAddress,
                                        persistentId,
                                        clientId);
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
                    userProfile,
                    rpPairwiseSubject,
                    userIdentityUserInfo,
                    clientId);

            auditService.submitAuditEvent(IPVAuditableEvent.IPV_SPOT_REQUESTED, clientId, user);
            segmentedFunctionCall(
                    "saveIdentityClaims",
                    () ->
                            ipvCallbackHelper.saveIdentityClaimsToDynamo(
                                    clientSessionId, rpPairwiseSubject, userIdentityUserInfo));
            var redirectURI = frontend.ipvCallbackURI();
            LOG.info("Successful IPV callback. Redirecting to frontend");
            return generateApiGatewayProxyResponse(
                    302, "", Map.of(ResponseHeaders.LOCATION, redirectURI.toString()), null);
        } catch (NoSessionException e) {
            LOG.warn(e.getMessage());
            return RedirectService.redirectToFrontendErrorPage(frontend.errorIpvCallbackURI());
        } catch (IpvCallbackException | UnsuccessfulCredentialResponseException e) {
            LOG.warn(e.getMessage());
            return RedirectService.redirectToFrontendErrorPage(frontend.errorURI());
        } catch (ParseException e) {
            LOG.info("Cannot retrieve auth request params from client session id");
            return RedirectService.redirectToFrontendErrorPage(frontend.errorURI());
        } catch (JsonException e) {
            LOG.error("Unable to serialize SPOTRequest when placing on queue");
            return RedirectService.redirectToFrontendErrorPage(frontend.errorURI());
        } catch (UserNotFoundException e) {
            LOG.error(e.getMessage());
            throw new RuntimeException(e);
        }
    }

    private static Optional<UserInfo> getAuthUserInfo(
            AuthenticationUserInfoStorageService authUserInfoStorageService,
            String internalCommonSubjectId,
            String clientSessionId) {
        try {
            return authUserInfoStorageService.getAuthenticationUserInfo(
                    internalCommonSubjectId, clientSessionId);
        } catch (ParseException e) {
            // TODO: ATO-1117: temporary logs. authUserInfo is not essential, so we don't want this
            // to exit the lambda yet.
            LOG.info("error parsing authUserInfo. Message: {}", e.getMessage());
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

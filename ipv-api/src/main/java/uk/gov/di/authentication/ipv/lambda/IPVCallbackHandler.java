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
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
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
import uk.gov.di.orchestration.shared.services.AuditService;
import uk.gov.di.orchestration.shared.services.ClientSessionService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.DynamoClientService;
import uk.gov.di.orchestration.shared.services.DynamoService;
import uk.gov.di.orchestration.shared.services.KmsConnectionService;
import uk.gov.di.orchestration.shared.services.NoSessionOrchestrationService;
import uk.gov.di.orchestration.shared.services.RedisConnectionService;
import uk.gov.di.orchestration.shared.services.SerializationService;
import uk.gov.di.orchestration.shared.services.SessionService;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import static com.nimbusds.oauth2.sdk.OAuth2Error.ACCESS_DENIED_CODE;
import static uk.gov.di.orchestration.shared.entity.ValidClaims.RETURN_CODE;
import static uk.gov.di.orchestration.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
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
    private final DynamoService dynamoService;
    private final ClientSessionService clientSessionService;
    private final DynamoClientService dynamoClientService;
    private final AuditService auditService;
    private final IPVCallbackHelper ipvCallbackHelper;
    private final NoSessionOrchestrationService noSessionOrchestrationService;
    protected final Json objectMapper = SerializationService.getInstance();
    private static final String REDIRECT_PATH = "ipv-callback";
    private static final String ERROR_PAGE_REDIRECT_PATH = "error";
    private static final String ERROR_PAGE_REDIRECT_PATH_NO_SESSION =
            "ipv-callback-session-expiry-error";
    private final CookieHelper cookieHelper;

    public IPVCallbackHandler() {
        this(ConfigurationService.getInstance());
    }

    public IPVCallbackHandler(
            ConfigurationService configurationService,
            IPVAuthorisationService responseService,
            IPVTokenService ipvTokenService,
            SessionService sessionService,
            DynamoService dynamoService,
            ClientSessionService clientSessionService,
            DynamoClientService dynamoClientService,
            AuditService auditService,
            CookieHelper cookieHelper,
            NoSessionOrchestrationService noSessionOrchestrationService,
            IPVCallbackHelper ipvCallbackHelper) {
        this.configurationService = configurationService;
        this.ipvAuthorisationService = responseService;
        this.ipvTokenService = ipvTokenService;
        this.sessionService = sessionService;
        this.dynamoService = dynamoService;
        this.clientSessionService = clientSessionService;
        this.dynamoClientService = dynamoClientService;
        this.auditService = auditService;
        this.cookieHelper = cookieHelper;
        this.noSessionOrchestrationService = noSessionOrchestrationService;
        this.ipvCallbackHelper = ipvCallbackHelper;
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
        this.dynamoService = new DynamoService(configurationService);
        this.clientSessionService = new ClientSessionService(configurationService);
        this.dynamoClientService = new DynamoClientService(configurationService);
        this.auditService = new AuditService(configurationService);
        this.cookieHelper = new CookieHelper();
        this.noSessionOrchestrationService =
                new NoSessionOrchestrationService(configurationService);
        this.ipvCallbackHelper = new IPVCallbackHelper(configurationService);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        ThreadContext.clearMap();
        LOG.info("Request received to IPVCallbackHandler");
        try {
            if (!configurationService.isIdentityEnabled()) {
                throw new IpvCallbackException("Identity is not enabled");
            }
            var sessionCookiesIds =
                    cookieHelper.parseSessionCookie(input.getHeaders()).orElse(null);
            if (Objects.isNull(sessionCookiesIds)) {
                var noSessionEntity =
                        noSessionOrchestrationService.generateNoSessionOrchestrationEntity(
                                input.getQueryStringParameters(),
                                configurationService.isIPVNoSessionResponseEnabled());
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
            var session =
                    sessionService
                            .readSessionFromRedis(sessionCookiesIds.getSessionId())
                            .orElseThrow(
                                    () -> new IPVCallbackNoSessionException("Session not found"));

            attachSessionIdToLogs(session);
            var persistentId =
                    PersistentIdHelper.extractPersistentIdFromCookieHeader(input.getHeaders());
            attachLogFieldToLogs(PERSISTENT_SESSION_ID, persistentId);
            var clientSessionId = sessionCookiesIds.getClientSessionId();
            attachLogFieldToLogs(CLIENT_SESSION_ID, clientSessionId);
            attachLogFieldToLogs(GOVUK_SIGNIN_JOURNEY_ID, clientSessionId);
            var clientSession =
                    clientSessionService
                            .getClientSession(clientSessionId)
                            .orElseThrow(
                                    () ->
                                            new IPVCallbackNoSessionException(
                                                    "ClientSession not found"));

            var authRequest = AuthenticationRequest.parse(clientSession.getAuthRequestParams());
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
                                            input.getQueryStringParameters(),
                                            session.getSessionId()));
            var userProfile =
                    dynamoService
                            .getUserProfileFromEmail(session.getEmailAddress())
                            .orElseThrow(
                                    () ->
                                            new IpvCallbackException(
                                                    "Email from session does not have a user profile"));
            var rpPairwiseSubject =
                    ClientSubjectHelper.getSubject(
                            userProfile,
                            clientRegistry,
                            dynamoService,
                            configurationService.getInternalSectorUri());

            var internalPairwiseSubjectId =
                    ClientSubjectHelper.calculatePairwiseIdentifier(
                            userProfile.getSubjectID(),
                            URI.create(configurationService.getInternalSectorUri()),
                            dynamoService.getOrGenerateSalt(userProfile));

            var ipAddress = IpAddressHelper.extractIpAddress(input);
            var auditContext =
                    new AuditContext(
                            clientSessionId,
                            session.getSessionId(),
                            clientId,
                            internalPairwiseSubjectId,
                            session.getEmailAddress(),
                            ipAddress,
                            Objects.isNull(userProfile.getPhoneNumber())
                                    ? AuditService.UNKNOWN
                                    : userProfile.getPhoneNumber(),
                            persistentId);

            if (errorObject.isPresent()) {
                var accountInterventionStatus =
                        ipvCallbackHelper.getAccountInterventionStatus(
                                internalPairwiseSubjectId, auditContext);
                if (configurationService.isAccountInterventionServiceActionEnabled()) {
                    ipvCallbackHelper.doAccountIntervention(accountInterventionStatus);
                }

                return ipvCallbackHelper.generateAuthenticationErrorResponse(
                        authRequest,
                        new ErrorObject(ACCESS_DENIED_CODE, errorObject.get().getDescription()),
                        false,
                        clientSessionId,
                        session.getSessionId());
            }

            auditService.submitAuditEvent(
                    IPVAuditableEvent.IPV_AUTHORISATION_RESPONSE_RECEIVED,
                    clientSessionId,
                    session.getSessionId(),
                    clientId,
                    internalPairwiseSubjectId,
                    userProfile.getEmail(),
                    AuditService.UNKNOWN,
                    userProfile.getPhoneNumber(),
                    persistentId);

            var tokenRequest =
                    segmentedFunctionCall(
                            "constructTokenRequest",
                            () ->
                                    ipvTokenService.constructTokenRequest(
                                            input.getQueryStringParameters().get("code")));
            var tokenResponse =
                    segmentedFunctionCall(
                            "sendIpvTokenRequest",
                            () -> ipvTokenService.sendTokenRequest(tokenRequest));
            if (!tokenResponse.indicatesSuccess()) {
                LOG.error(
                        "IPV TokenResponse was not successful: {}",
                        tokenResponse.toErrorResponse().toJSONObject());
                auditService.submitAuditEvent(
                        IPVAuditableEvent.IPV_UNSUCCESSFUL_TOKEN_RESPONSE_RECEIVED,
                        clientSessionId,
                        session.getSessionId(),
                        clientId,
                        internalPairwiseSubjectId,
                        userProfile.getEmail(),
                        AuditService.UNKNOWN,
                        userProfile.getPhoneNumber(),
                        persistentId);
                return redirectToFrontendErrorPage();
            }
            auditService.submitAuditEvent(
                    IPVAuditableEvent.IPV_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED,
                    clientSessionId,
                    session.getSessionId(),
                    clientId,
                    internalPairwiseSubjectId,
                    userProfile.getEmail(),
                    AuditService.UNKNOWN,
                    userProfile.getPhoneNumber(),
                    persistentId);

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
                    IPVAuditableEvent.IPV_SUCCESSFUL_IDENTITY_RESPONSE_RECEIVED,
                    clientSessionId,
                    session.getSessionId(),
                    clientId,
                    internalPairwiseSubjectId,
                    userProfile.getEmail(),
                    AuditService.UNKNOWN,
                    userProfile.getPhoneNumber(),
                    persistentId);
            var userIdentityError =
                    ipvCallbackHelper.validateUserIdentityResponse(userIdentityUserInfo);
            if (userIdentityError.isPresent()) {
                var accountInterventionStatus =
                        ipvCallbackHelper.getAccountInterventionStatus(
                                internalPairwiseSubjectId, auditContext);
                if (configurationService.isAccountInterventionServiceActionEnabled()) {
                    ipvCallbackHelper.doAccountIntervention(accountInterventionStatus);
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
                                        clientSession,
                                        rpPairwiseSubject,
                                        internalPairwiseSubjectId,
                                        userIdentityUserInfo,
                                        ipAddress,
                                        persistentId);
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
                            session.getSessionId(),
                            persistentId,
                            context.getAwsRequestId(),
                            clientId,
                            clientSessionId);
            ipvCallbackHelper.queueSPOTRequest(
                    logIds,
                    getSectorIdentifierForClient(
                            clientRegistry, configurationService.getInternalSectorUri()),
                    userProfile,
                    rpPairwiseSubject,
                    userIdentityUserInfo,
                    clientId);

            auditService.submitAuditEvent(
                    IPVAuditableEvent.IPV_SPOT_REQUESTED,
                    clientSessionId,
                    session.getSessionId(),
                    clientId,
                    internalPairwiseSubjectId,
                    userProfile.getEmail(),
                    AuditService.UNKNOWN,
                    userProfile.getPhoneNumber(),
                    persistentId);
            segmentedFunctionCall(
                    "saveIdentityClaims",
                    () ->
                            ipvCallbackHelper.saveIdentityClaimsToDynamo(
                                    rpPairwiseSubject, userIdentityUserInfo));
            var redirectURI =
                    ConstructUriHelper.buildURI(
                            configurationService.getLoginURI().toString(), REDIRECT_PATH);
            LOG.info("Successful IPV callback. Redirecting to frontend");
            return generateApiGatewayProxyResponse(
                    302, "", Map.of(ResponseHeaders.LOCATION, redirectURI.toString()), null);
        } catch (NoSessionException e) {
            LOG.warn(e.getMessage());
            return redirectToFrontendErrorPage(ERROR_PAGE_REDIRECT_PATH_NO_SESSION);
        } catch (IpvCallbackException | UnsuccessfulCredentialResponseException e) {
            LOG.warn(e.getMessage());
            return redirectToFrontendErrorPage();
        } catch (ParseException e) {
            LOG.info("Cannot retrieve auth request params from client session id");
            return redirectToFrontendErrorPage();
        } catch (JsonException e) {
            LOG.error("Unable to serialize SPOTRequest when placing on queue");
            return redirectToFrontendErrorPage();
        } catch (UserNotFoundException e) {
            LOG.error(e.getMessage());
            throw new RuntimeException(e);
        }
    }

    private static boolean returnCodePresentInIPVResponse(Object returnCode) {
        return returnCode instanceof List<?> returnCodeList && !returnCodeList.isEmpty();
    }

    private APIGatewayProxyResponseEvent redirectToFrontendErrorPage() {
        return redirectToFrontendErrorPage(ERROR_PAGE_REDIRECT_PATH);
    }

    private APIGatewayProxyResponseEvent redirectToFrontendErrorPage(String errorPagePath) {
        LOG.info("Redirecting to frontend error page: {}", errorPagePath);
        return generateApiGatewayProxyResponse(
                302,
                "",
                Map.of(
                        ResponseHeaders.LOCATION,
                        ConstructUriHelper.buildURI(
                                        configurationService.getLoginURI().toString(),
                                        errorPagePath)
                                .toString()),
                null);
    }

    private boolean rpRequestedReturnCode(
            ClientRegistry clientRegistry, AuthenticationRequest authRequest) {
        return clientRegistry.getClaims().contains(RETURN_CODE.getValue())
                && authRequest
                                .getOIDCClaims()
                                .getUserInfoClaimsRequest()
                                .get(RETURN_CODE.getValue())
                        != null;
    }
}

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
import uk.gov.di.authentication.ipv.domain.IPVAuditableEvent;
import uk.gov.di.authentication.ipv.entity.IpvCallbackException;
import uk.gov.di.authentication.ipv.entity.LogIds;
import uk.gov.di.authentication.ipv.entity.SPOTClaims;
import uk.gov.di.authentication.ipv.entity.SPOTRequest;
import uk.gov.di.authentication.ipv.services.IPVAuthorisationService;
import uk.gov.di.authentication.ipv.services.IPVTokenService;
import uk.gov.di.authentication.shared.entity.IdentityClaims;
import uk.gov.di.authentication.shared.entity.LevelOfConfidence;
import uk.gov.di.authentication.shared.entity.ResponseHeaders;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.ValidClaims;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.ConstructUriHelper;
import uk.gov.di.authentication.shared.helpers.CookieHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.serialization.Json.JsonException;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AwsSqsClient;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoClientService;
import uk.gov.di.authentication.shared.services.DynamoIdentityService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.shared.services.SessionService;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import static com.nimbusds.oauth2.sdk.OAuth2Error.ACCESS_DENIED_CODE;
import static uk.gov.di.authentication.shared.entity.IdentityClaims.VOT;
import static uk.gov.di.authentication.shared.entity.IdentityClaims.VTM;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.ClientSubjectHelper.getSectorIdentifierForClient;
import static uk.gov.di.authentication.shared.helpers.ConstructUriHelper.buildURI;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.CLIENT_SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.PERSISTENT_SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachSessionIdToLogs;
import static uk.gov.di.authentication.shared.helpers.WarmerHelper.isWarming;

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
    private final AwsSqsClient sqsClient;
    private final DynamoIdentityService dynamoIdentityService;
    protected final Json objectMapper = SerializationService.getInstance();
    private static final String REDIRECT_PATH = "ipv-callback";
    private static final String ERROR_PAGE_REDIRECT_PATH = "error";
    private final CookieHelperWrapper cookieHelperWrapper;

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
            AwsSqsClient sqsClient,
            DynamoIdentityService dynamoIdentityService,
            CookieHelperWrapper cookieHelperWrapper) {
        this.configurationService = configurationService;
        this.ipvAuthorisationService = responseService;
        this.ipvTokenService = ipvTokenService;
        this.sessionService = sessionService;
        this.dynamoService = dynamoService;
        this.clientSessionService = clientSessionService;
        this.dynamoClientService = dynamoClientService;
        this.auditService = auditService;
        this.sqsClient = sqsClient;
        this.dynamoIdentityService = dynamoIdentityService;
        this.cookieHelperWrapper = cookieHelperWrapper;
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
        this.sqsClient =
                new AwsSqsClient(
                        configurationService.getAwsRegion(),
                        configurationService.getSpotQueueUri(),
                        configurationService.getSqsEndpointUri());
        this.dynamoIdentityService = new DynamoIdentityService(configurationService);
        this.cookieHelperWrapper = CookieHelperWrapper.SINGLETON;
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return isWarming(input)
                .orElseGet(
                        () -> {
                            LOG.info("Request received to IPVCallbackHandler");
                            try {
                                if (!configurationService.isIdentityEnabled()) {
                                    throw new IpvCallbackException("Identity is not enabled");
                                }

                                CookieHelper.SessionCookieIds sessionCookiesIds =
                                        getSessionCookiesIds(input.getHeaders());

                                var session =
                                        sessionService
                                                .readSessionFromRedis(
                                                        sessionCookiesIds.getSessionId())
                                                .orElseThrow(
                                                        () -> {
                                                            throw new IpvCallbackException(
                                                                    "Session not found");
                                                        });
                                attachSessionIdToLogs(session);
                                var persistentId =
                                        PersistentIdHelper.extractPersistentIdFromCookieHeader(
                                                input.getHeaders());
                                attachLogFieldToLogs(PERSISTENT_SESSION_ID, persistentId);
                                var clientSession =
                                        clientSessionService
                                                .getClientSession(
                                                        sessionCookiesIds.getClientSessionId())
                                                .orElse(null);
                                if (Objects.isNull(clientSession)) {
                                    throw new IpvCallbackException("ClientSession not found");
                                }
                                attachLogFieldToLogs(
                                        CLIENT_SESSION_ID, sessionCookiesIds.getClientSessionId());
                                var authRequest =
                                        AuthenticationRequest.parse(
                                                clientSession.getAuthRequestParams());

                                var clientId = authRequest.getClientID().getValue();
                                var clientRegistry =
                                        dynamoClientService.getClient(clientId).orElse(null);
                                if (Objects.isNull(clientRegistry)) {
                                    throw new IpvCallbackException(
                                            "Client registry not found with given clientId");
                                }

                                var errorObject =
                                        ipvAuthorisationService.validateResponse(
                                                input.getQueryStringParameters(),
                                                session.getSessionId());
                                if (errorObject.isPresent()) {
                                    LOG.error(
                                            "Error in IPV AuthorisationResponse. ErrorCode: {}. ErrorDescription: {}",
                                            errorObject.get().getCode(),
                                            errorObject.get().getDescription());
                                    var errorResponse =
                                            new AuthenticationErrorResponse(
                                                    authRequest.getRedirectionURI(),
                                                    new ErrorObject(
                                                            ACCESS_DENIED_CODE,
                                                            errorObject.get().getDescription()),
                                                    authRequest.getState(),
                                                    authRequest.getResponseMode());
                                    return generateApiGatewayProxyResponse(
                                            302,
                                            "",
                                            Map.of(
                                                    ResponseHeaders.LOCATION,
                                                    errorResponse.toURI().toString()),
                                            null);
                                }
                                var userProfile =
                                        dynamoService
                                                .getUserProfileFromEmail(session.getEmailAddress())
                                                .orElse(null);
                                if (Objects.isNull(userProfile)) {
                                    throw new IpvCallbackException(
                                            "Email from session does not have a user profile");
                                }

                                auditService.submitAuditEvent(
                                        IPVAuditableEvent.IPV_AUTHORISATION_RESPONSE_RECEIVED,
                                        context.getAwsRequestId(),
                                        session.getSessionId(),
                                        clientId,
                                        userProfile.getSubjectID(),
                                        userProfile.getEmail(),
                                        AuditService.UNKNOWN,
                                        userProfile.getPhoneNumber(),
                                        persistentId);

                                var tokenRequest =
                                        ipvTokenService.constructTokenRequest(
                                                input.getQueryStringParameters().get("code"));
                                var tokenResponse = ipvTokenService.sendTokenRequest(tokenRequest);
                                if (tokenResponse.indicatesSuccess()) {
                                    auditService.submitAuditEvent(
                                            IPVAuditableEvent
                                                    .IPV_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED,
                                            context.getAwsRequestId(),
                                            session.getSessionId(),
                                            clientId,
                                            userProfile.getSubjectID(),
                                            userProfile.getEmail(),
                                            AuditService.UNKNOWN,
                                            userProfile.getPhoneNumber(),
                                            persistentId);
                                } else {
                                    LOG.error(
                                            "IPV TokenResponse was not successful: {}",
                                            tokenResponse.toErrorResponse().toJSONObject());
                                    auditService.submitAuditEvent(
                                            IPVAuditableEvent
                                                    .IPV_UNSUCCESSFUL_TOKEN_RESPONSE_RECEIVED,
                                            context.getAwsRequestId(),
                                            session.getSessionId(),
                                            clientId,
                                            userProfile.getSubjectID(),
                                            userProfile.getEmail(),
                                            AuditService.UNKNOWN,
                                            userProfile.getPhoneNumber(),
                                            persistentId);
                                    return redirectToFrontendErrorPage();
                                }
                                var pairwiseSubject =
                                        ClientSubjectHelper.getSubject(
                                                userProfile, clientRegistry, dynamoService);
                                var userIdentityUserInfo =
                                        ipvTokenService.sendIpvUserIdentityRequest(
                                                new UserInfoRequest(
                                                        ConstructUriHelper.buildURI(
                                                                configurationService
                                                                        .getIPVBackendURI()
                                                                        .toString(),
                                                                "user-identity"),
                                                        tokenResponse
                                                                .toSuccessResponse()
                                                                .getTokens()
                                                                .getBearerAccessToken()));
                                LOG.info(userIdentityUserInfo);
                                if (Objects.isNull(userIdentityUserInfo)) {
                                    throw new IpvCallbackException(
                                            "IPV UserIdentityRequest failed");
                                }
                                if (configurationService.isIdentityTraceLoggingEnabled()) {
                                    LOG.info(
                                            "IPV UserIdentityRequest succeeded: {}",
                                            userIdentityUserInfo.toJSONObject().toJSONString());
                                }
                                auditService.submitAuditEvent(
                                        IPVAuditableEvent.IPV_SUCCESSFUL_IDENTITY_RESPONSE_RECEIVED,
                                        context.getAwsRequestId(),
                                        session.getSessionId(),
                                        clientId,
                                        userProfile.getSubjectID(),
                                        userProfile.getEmail(),
                                        AuditService.UNKNOWN,
                                        userProfile.getPhoneNumber(),
                                        persistentId);

                                if (configurationService.isSpotEnabled()) {
                                    Optional<ErrorObject> userIdentityError =
                                            validateUserIdentityResponse(userIdentityUserInfo);
                                    if (userIdentityError.isEmpty()) {
                                        LOG.info("SPOT will be invoked.");
                                        var logIds =
                                                new LogIds(
                                                        session.getSessionId(),
                                                        persistentId,
                                                        context.getAwsRequestId(),
                                                        clientId,
                                                        sessionCookiesIds.getClientSessionId());
                                        queueSPOTRequest(
                                                logIds,
                                                getSectorIdentifierForClient(clientRegistry),
                                                userProfile,
                                                pairwiseSubject,
                                                userIdentityUserInfo,
                                                clientId);

                                        auditService.submitAuditEvent(
                                                IPVAuditableEvent.IPV_SPOT_REQUESTED,
                                                context.getAwsRequestId(),
                                                session.getSessionId(),
                                                clientId,
                                                userProfile.getSubjectID(),
                                                userProfile.getEmail(),
                                                AuditService.UNKNOWN,
                                                userProfile.getPhoneNumber(),
                                                persistentId);
                                    } else {
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
                                                Map.of(
                                                        ResponseHeaders.LOCATION,
                                                        errorResponse.toURI().toString()),
                                                null);
                                    }
                                }
                                saveAdditionalClaimsToDynamo(pairwiseSubject, userIdentityUserInfo);
                                var redirectURI =
                                        ConstructUriHelper.buildURI(
                                                configurationService.getLoginURI().toString(),
                                                REDIRECT_PATH);
                                return generateApiGatewayProxyResponse(
                                        302,
                                        "",
                                        Map.of(ResponseHeaders.LOCATION, redirectURI.toString()),
                                        null);
                            } catch (IpvCallbackException e) {
                                LOG.warn(e.getMessage());
                                return redirectToFrontendErrorPage();
                            } catch (ParseException e) {
                                LOG.info(
                                        "Cannot retrieve auth request params from client session id");
                                return redirectToFrontendErrorPage();
                            } catch (JsonException e) {
                                LOG.error("Unable to serialize SPOTRequest when placing on queue");
                                return redirectToFrontendErrorPage();
                            }
                        });
    }

    private CookieHelper.SessionCookieIds getSessionCookiesIds(Map<String, String> input)
            throws IpvCallbackException {
        try {
            return cookieHelperWrapper.staticParseCookie(input).get();
        } catch (Exception e) {
            throw new IpvCallbackException("Failed to parse cookie Ids");
        }
    }

    private void saveAdditionalClaimsToDynamo(
            Subject pairwiseIdentifier, UserInfo userIdentityUserInfo) {
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
        dynamoIdentityService.addAdditionalClaims(pairwiseIdentifier.getValue(), additionalClaims);
    }

    private Optional<ErrorObject> validateUserIdentityResponse(UserInfo userIdentityUserInfo) {
        if (!LevelOfConfidence.MEDIUM_LEVEL
                .getValue()
                .equals(userIdentityUserInfo.getClaim(VOT.getValue()))) {
            LOG.warn("IPV missing vot or vot not P2.");
            return Optional.of(OAuth2Error.ACCESS_DENIED);
        }
        var trustmark =
                buildURI(configurationService.getOidcApiBaseURL().orElseThrow(), "/trustmark")
                        .toString();

        if (!trustmark.equals(userIdentityUserInfo.getClaim(VTM.getValue()))) {
            throw new IpvCallbackException("IPV trustmark is invalid");
        }
        return Optional.empty();
    }

    private void queueSPOTRequest(
            LogIds logIds,
            String sectorIdentifier,
            UserProfile userProfile,
            Subject pairwiseSubject,
            UserInfo userIdentityUserInfo,
            String clientId)
            throws JsonException {

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
                        .withVtm(
                                buildURI(
                                                configurationService
                                                        .getOidcApiBaseURL()
                                                        .orElseThrow(),
                                                "/trustmark")
                                        .toString());

        var spotRequest =
                new SPOTRequest(
                        spotClaimsBuilder.build(),
                        userProfile.getSubjectID(),
                        dynamoService.getOrGenerateSalt(userProfile),
                        sectorIdentifier,
                        pairwiseSubject.getValue(),
                        logIds,
                        clientId);
        var spotRequestString = objectMapper.writeValueAsString(spotRequest);
        sqsClient.send(spotRequestString);
        if (configurationService.isIdentityTraceLoggingEnabled()) {
            LOG.info("SPOT request placed on queue: {}", spotRequestString);
        } else {
            LOG.info("SPOT request placed on queue");
        }
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

class CookieHelperWrapper {
    public static final CookieHelperWrapper SINGLETON = new CookieHelperWrapper();

    public Optional<CookieHelper.SessionCookieIds> staticParseCookie(Map<String, String> input) {
        return CookieHelper.parseSessionCookie(input);
    }
}

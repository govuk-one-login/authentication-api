package uk.gov.di.authentication.ipv.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.ipv.domain.IPVAuditableEvent;
import uk.gov.di.authentication.ipv.entity.LogIds;
import uk.gov.di.authentication.ipv.entity.SPOTClaims;
import uk.gov.di.authentication.ipv.entity.SPOTRequest;
import uk.gov.di.authentication.ipv.services.IPVAuthorisationService;
import uk.gov.di.authentication.ipv.services.IPVTokenService;
import uk.gov.di.authentication.shared.entity.LevelOfConfidence;
import uk.gov.di.authentication.shared.entity.ResponseHeaders;
import uk.gov.di.authentication.shared.entity.UserProfile;
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
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.SessionService;

import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Objects;

import static com.nimbusds.oauth2.sdk.OAuth2Error.ACCESS_DENIED_CODE;
import static uk.gov.di.authentication.shared.entity.IdentityClaims.VOT;
import static uk.gov.di.authentication.shared.entity.IdentityClaims.VTM;
import static uk.gov.di.authentication.shared.helpers.ClientSubjectHelper.getSectorIdentifierForClient;
import static uk.gov.di.authentication.shared.helpers.ConstructUriHelper.buildURI;
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
    protected final Json objectMapper = Json.jackson();
    private static final String REDIRECT_PATH = "ipv-callback";

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
            AwsSqsClient sqsClient) {
        this.configurationService = configurationService;
        this.ipvAuthorisationService = responseService;
        this.ipvTokenService = ipvTokenService;
        this.sessionService = sessionService;
        this.dynamoService = dynamoService;
        this.clientSessionService = clientSessionService;
        this.dynamoClientService = dynamoClientService;
        this.auditService = auditService;
        this.sqsClient = sqsClient;
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
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return isWarming(input)
                .orElseGet(
                        () -> {
                            LOG.info("Request received to IPVCallbackHandler");
                            try {
                                var sessionCookiesIds =
                                        CookieHelper.parseSessionCookie(input.getHeaders())
                                                .orElseThrow();
                                var session =
                                        sessionService
                                                .readSessionFromRedis(
                                                        sessionCookiesIds.getSessionId())
                                                .orElseThrow();
                                var persistentId =
                                        PersistentIdHelper.extractPersistentIdFromCookieHeader(
                                                input.getHeaders());
                                var clientSession =
                                        clientSessionService
                                                .getClientSession(
                                                        sessionCookiesIds.getClientSessionId())
                                                .orElse(null);
                                if (Objects.isNull(clientSession)) {
                                    LOG.error("ClientSession not found");
                                    throw new RuntimeException();
                                }
                                var authRequest =
                                        AuthenticationRequest.parse(
                                                clientSession.getAuthRequestParams());

                                var clientId = authRequest.getClientID().getValue();
                                var clientRegistry =
                                        dynamoClientService.getClient(clientId).orElse(null);
                                if (Objects.isNull(clientRegistry)) {
                                    LOG.error("Client registry not found with given clientId");
                                    throw new RuntimeException(
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
                                    return new APIGatewayProxyResponseEvent()
                                            .withStatusCode(302)
                                            .withHeaders(
                                                    Map.of(
                                                            ResponseHeaders.LOCATION,
                                                            errorResponse.toURI().toString()));
                                }
                                var userProfile =
                                        dynamoService
                                                .getUserProfileFromEmail(session.getEmailAddress())
                                                .orElse(null);
                                if (Objects.isNull(userProfile)) {
                                    LOG.error("Email from session does not have a user profile");
                                    throw new RuntimeException(
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
                                    throw new RuntimeException(
                                            "IPV TokenResponse was not successful");
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
                                if (Objects.isNull(userIdentityUserInfo)) {
                                    LOG.error("IPV UserIdentityRequest failed.");
                                    throw new RuntimeException("IPV UserIdentityRequest failed.");
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
                                    if (isUserIdentityGoingToSpot(userIdentityUserInfo)) {
                                        var logIds =
                                                new LogIds(
                                                        session.getSessionId(),
                                                        persistentId,
                                                        context.getAwsRequestId(),
                                                        clientId);
                                        queueSPOTRequest(
                                                logIds,
                                                getSectorIdentifierForClient(clientRegistry),
                                                userProfile,
                                                pairwiseSubject,
                                                userIdentityUserInfo);

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
                                        LOG.info("SPOT will not be invoked.");
                                    }
                                }
                                var redirectURI =
                                        ConstructUriHelper.buildURI(
                                                configurationService.getLoginURI().toString(),
                                                REDIRECT_PATH);
                                return new APIGatewayProxyResponseEvent()
                                        .withStatusCode(302)
                                        .withHeaders(
                                                Map.of(
                                                        ResponseHeaders.LOCATION,
                                                        redirectURI.toString()));
                            } catch (NoSuchElementException e) {
                                LOG.error("Session not found");
                                throw new RuntimeException("Session not found", e);
                            } catch (ParseException e) {
                                LOG.info(
                                        "Cannot retrieve auth request params from client session id");
                                throw new RuntimeException();
                            } catch (JsonException e) {
                                LOG.error("Unable to serialize SPOTRequest when placing on queue");
                                throw new RuntimeException(e);
                            }
                        });
    }

    private boolean isUserIdentityGoingToSpot(UserInfo userIdentityUserInfo) {
        if (!LevelOfConfidence.MEDIUM_LEVEL
                .getValue()
                .equals(userIdentityUserInfo.getClaim(VOT.getValue()))) {
            LOG.info("IPV missing vot or vot not P2.");
            return false;
        }
        var trustmark =
                buildURI(configurationService.getOidcApiBaseURL().orElseThrow(), "/trustmark")
                        .toString();

        if (!trustmark.equals(userIdentityUserInfo.getClaim(VTM.getValue()))) {
            LOG.info("IPV trustmark is invalid.");
            return false;
        }
        return true;
    }

    private void queueSPOTRequest(
            LogIds logIds,
            String sectorIdentifier,
            UserProfile userProfile,
            Subject pairwiseSubject,
            UserInfo userIdentityUserInfo)
            throws JsonException {

        var spotClaimsBuilder =
                SPOTClaims.builder()
                        .withClaims(userIdentityUserInfo.toJSONObject())
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
                        logIds);
        sqsClient.send(objectMapper.writeValueAsString(spotRequest));
        LOG.info("SPOT request placed on queue");
    }
}

package uk.gov.di.authentication.ipv.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
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
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.ConstructUriHelper;
import uk.gov.di.authentication.shared.helpers.CookieHelper;
import uk.gov.di.authentication.shared.helpers.ObjectMapperFactory;
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
    protected final ObjectMapper objectMapper = ObjectMapperFactory.getInstance();
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
        this.configurationService = configurationService;
        this.ipvAuthorisationService =
                new IPVAuthorisationService(
                        configurationService, new RedisConnectionService(configurationService));
        this.ipvTokenService =
                new IPVTokenService(
                        configurationService, new KmsConnectionService(configurationService));
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
                                var clientSession =
                                        clientSessionService.getClientSession(
                                                sessionCookiesIds.getClientSessionId());
                                if (Objects.isNull(clientSession)) {
                                    LOG.error("ClientSession not found");
                                    throw new RuntimeException();
                                }
                                var clientId =
                                        AuthenticationRequest.parse(
                                                        clientSession.getAuthRequestParams())
                                                .getClientID()
                                                .getValue();
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
                                    throw new RuntimeException(
                                            "Error in IPV AuthorisationResponse");
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
                                        AuditService.UNKNOWN);

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
                                            AuditService.UNKNOWN);
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
                                            AuditService.UNKNOWN);
                                    throw new RuntimeException(
                                            "IPV TokenResponse was not successful");
                                }
                                var pairwiseSubject =
                                        ClientSubjectHelper.getSubject(
                                                userProfile, clientRegistry, dynamoService);
                                var ipvInfoResponse =
                                        ipvTokenService.sendIpvUserIdentityRequest(
                                                tokenResponse
                                                        .toSuccessResponse()
                                                        .getTokens()
                                                        .getBearerAccessToken());
                                auditService.submitAuditEvent(
                                        IPVAuditableEvent.IPV_SUCCESSFUL_IDENTITY_RESPONSE_RECEIVED,
                                        context.getAwsRequestId(),
                                        session.getSessionId(),
                                        clientId,
                                        userProfile.getSubjectID(),
                                        userProfile.getEmail(),
                                        AuditService.UNKNOWN,
                                        userProfile.getPhoneNumber(),
                                        AuditService.UNKNOWN);
                                var spotRequest =
                                        new SPOTRequest(
                                                new SPOTClaims(
                                                        LevelOfConfidence.MEDIUM_LEVEL.getValue(),
                                                        buildURI(
                                                                        configurationService
                                                                                .getOidcApiBaseURL()
                                                                                .orElseThrow(),
                                                                        "/trustmark")
                                                                .toString()),
                                                userProfile.getSubjectID(),
                                                dynamoService.getOrGenerateSalt(userProfile),
                                                pairwiseSubject.getValue(),
                                                new LogIds(session.getSessionId()));
                                if (configurationService.isSpotEnabled()) {
                                    sqsClient.send(objectMapper.writeValueAsString(spotRequest));
                                    LOG.info("SPOT request placed on queue");
                                }
                                auditService.submitAuditEvent(
                                        IPVAuditableEvent.IPV_SPOT_REQUESTED,
                                        context.getAwsRequestId(),
                                        session.getSessionId(),
                                        clientId,
                                        userProfile.getSubjectID(),
                                        userProfile.getEmail(),
                                        AuditService.UNKNOWN,
                                        userProfile.getPhoneNumber(),
                                        AuditService.UNKNOWN);
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
                            } catch (JsonProcessingException e) {
                                LOG.error("Unable to serialize SPOTRequest when placing on queue");
                                throw new RuntimeException(e);
                            }
                        });
    }
}

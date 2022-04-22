package uk.gov.di.authentication.app.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.app.domain.DocAppAuditableEvent;
import uk.gov.di.authentication.app.services.DocAppAuthorisationService;
import uk.gov.di.authentication.app.services.DocAppTokenService;
import uk.gov.di.authentication.shared.entity.ResponseHeaders;
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

import static uk.gov.di.authentication.shared.helpers.WarmerHelper.isWarming;

public class DocAppCallbackHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(DocAppCallbackHandler.class);
    private final ConfigurationService configurationService;
    private final DocAppAuthorisationService authorisationService;
    private final DocAppTokenService tokenService;
    private final SessionService sessionService;
    private final DynamoService dynamoService;
    private final ClientSessionService clientSessionService;
    private final DynamoClientService dynamoClientService;
    private final AuditService auditService;
    private final AwsSqsClient sqsClient;
    protected final ObjectMapper objectMapper = ObjectMapperFactory.getInstance();
    private static final String REDIRECT_PATH = "doc-checking-app-callback";

    public DocAppCallbackHandler() {
        this(ConfigurationService.getInstance());
    }

    public DocAppCallbackHandler(
            ConfigurationService configurationService,
            DocAppAuthorisationService responseService,
            DocAppTokenService tokenService,
            SessionService sessionService,
            DynamoService dynamoService,
            ClientSessionService clientSessionService,
            DynamoClientService dynamoClientService,
            AuditService auditService,
            AwsSqsClient sqsClient) {
        this.configurationService = configurationService;
        this.authorisationService = responseService;
        this.tokenService = tokenService;
        this.sessionService = sessionService;
        this.dynamoService = dynamoService;
        this.clientSessionService = clientSessionService;
        this.dynamoClientService = dynamoClientService;
        this.auditService = auditService;
        this.sqsClient = sqsClient;
    }

    public DocAppCallbackHandler(ConfigurationService configurationService) {
        var kmsConnectionService = new KmsConnectionService(configurationService);
        this.configurationService = configurationService;
        this.authorisationService =
                new DocAppAuthorisationService(
                        configurationService,
                        new RedisConnectionService(configurationService),
                        kmsConnectionService);
        this.tokenService = new DocAppTokenService(configurationService, kmsConnectionService);
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
                            LOG.info("Request received to DocAppCallbackHandler");
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
                                        authorisationService.validateResponse(
                                                input.getQueryStringParameters(),
                                                session.getSessionId());
                                if (errorObject.isPresent()) {
                                    LOG.error(
                                            "Error in Doc App AuthorisationResponse. ErrorCode: {}. ErrorDescription: {}",
                                            errorObject.get().getCode(),
                                            errorObject.get().getDescription());
                                    throw new RuntimeException(
                                            "Error in Doc App AuthorisationResponse");
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
                                        DocAppAuditableEvent
                                                .DOC_APP_AUTHORISATION_RESPONSE_RECEIVED,
                                        context.getAwsRequestId(),
                                        session.getSessionId(),
                                        clientId,
                                        userProfile.getSubjectID(),
                                        userProfile.getEmail(),
                                        AuditService.UNKNOWN,
                                        userProfile.getPhoneNumber(),
                                        AuditService.UNKNOWN);

                                var tokenRequest =
                                        tokenService.constructTokenRequest(
                                                input.getQueryStringParameters().get("code"));
                                var tokenResponse = tokenService.sendTokenRequest(tokenRequest);
                                if (tokenResponse.indicatesSuccess()) {
                                    auditService.submitAuditEvent(
                                            DocAppAuditableEvent
                                                    .DOC_APP_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED,
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
                                            "Doc App TokenResponse was not successful: {}",
                                            tokenResponse.toErrorResponse().toJSONObject());
                                    auditService.submitAuditEvent(
                                            DocAppAuditableEvent
                                                    .DOC_APP_UNSUCCESSFUL_TOKEN_RESPONSE_RECEIVED,
                                            context.getAwsRequestId(),
                                            session.getSessionId(),
                                            clientId,
                                            userProfile.getSubjectID(),
                                            userProfile.getEmail(),
                                            AuditService.UNKNOWN,
                                            userProfile.getPhoneNumber(),
                                            AuditService.UNKNOWN);
                                    throw new RuntimeException(
                                            "Doc App TokenResponse was not successful");
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
                            }
                        });
    }
}

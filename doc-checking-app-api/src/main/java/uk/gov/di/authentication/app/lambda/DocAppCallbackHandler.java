package uk.gov.di.authentication.app.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.app.domain.DocAppAuditableEvent;
import uk.gov.di.authentication.app.exception.UnsuccesfulCredentialResponseException;
import uk.gov.di.authentication.app.services.DocAppAuthorisationService;
import uk.gov.di.authentication.app.services.DocAppCriService;
import uk.gov.di.authentication.app.services.DynamoDocAppService;
import uk.gov.di.authentication.shared.entity.ResponseHeaders;
import uk.gov.di.authentication.shared.helpers.ConstructUriHelper;
import uk.gov.di.authentication.shared.helpers.CookieHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.shared.services.SessionService;

import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Objects;

import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.authentication.shared.helpers.WarmerHelper.isWarming;

public class DocAppCallbackHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(DocAppCallbackHandler.class);
    private final ConfigurationService configurationService;
    private final DocAppAuthorisationService authorisationService;
    private final DocAppCriService tokenService;
    private final SessionService sessionService;
    private final ClientSessionService clientSessionService;
    private final AuditService auditService;
    private final DynamoDocAppService dynamoDocAppService;
    protected final Json objectMapper = SerializationService.getInstance();
    private static final String REDIRECT_PATH = "doc-checking-app-callback";

    public DocAppCallbackHandler() {
        this(ConfigurationService.getInstance());
    }

    public DocAppCallbackHandler(
            ConfigurationService configurationService,
            DocAppAuthorisationService responseService,
            DocAppCriService tokenService,
            SessionService sessionService,
            ClientSessionService clientSessionService,
            AuditService auditService,
            DynamoDocAppService dynamoDocAppService) {
        this.configurationService = configurationService;
        this.authorisationService = responseService;
        this.tokenService = tokenService;
        this.sessionService = sessionService;
        this.clientSessionService = clientSessionService;
        this.auditService = auditService;
        this.dynamoDocAppService = dynamoDocAppService;
    }

    public DocAppCallbackHandler(ConfigurationService configurationService) {
        var kmsConnectionService = new KmsConnectionService(configurationService);
        this.configurationService = configurationService;
        this.authorisationService =
                new DocAppAuthorisationService(
                        configurationService,
                        new RedisConnectionService(configurationService),
                        kmsConnectionService);
        this.tokenService = new DocAppCriService(configurationService, kmsConnectionService);
        this.sessionService = new SessionService(configurationService);
        this.clientSessionService = new ClientSessionService(configurationService);
        this.auditService = new AuditService(configurationService);
        this.dynamoDocAppService = new DynamoDocAppService(configurationService);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return segmentedFunctionCall(
                "doc-app-api::" + getClass().getSimpleName(),
                () -> docAppCallbackRequestHandler(input, context));
    }

    public APIGatewayProxyResponseEvent docAppCallbackRequestHandler(
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
                                        clientSessionService
                                                .getClientSession(
                                                        sessionCookiesIds.getClientSessionId())
                                                .orElse(null);
                                if (Objects.isNull(clientSession)) {
                                    LOG.error("ClientSession not found");
                                    throw new RuntimeException();
                                }
                                var clientId =
                                        AuthenticationRequest.parse(
                                                        clientSession.getAuthRequestParams())
                                                .getClientID()
                                                .getValue();

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

                                auditService.submitAuditEvent(
                                        DocAppAuditableEvent
                                                .DOC_APP_AUTHORISATION_RESPONSE_RECEIVED,
                                        context.getAwsRequestId(),
                                        session.getSessionId(),
                                        clientId,
                                        clientSession.getDocAppSubjectId().getValue(),
                                        AuditService.UNKNOWN,
                                        AuditService.UNKNOWN,
                                        AuditService.UNKNOWN,
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
                                            clientSession.getDocAppSubjectId().getValue(),
                                            AuditService.UNKNOWN,
                                            AuditService.UNKNOWN,
                                            AuditService.UNKNOWN,
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
                                            clientSession.getDocAppSubjectId().getValue(),
                                            AuditService.UNKNOWN,
                                            AuditService.UNKNOWN,
                                            AuditService.UNKNOWN,
                                            AuditService.UNKNOWN);
                                    throw new RuntimeException(
                                            "Doc App TokenResponse was not successful");
                                }

                                try {
                                    var credential =
                                            tokenService.sendCriDataRequest(
                                                    tokenResponse
                                                            .toSuccessResponse()
                                                            .getTokens()
                                                            .getAccessToken());
                                    auditService.submitAuditEvent(
                                            DocAppAuditableEvent
                                                    .DOC_APP_SUCCESSFUL_CREDENTIAL_RESPONSE_RECEIVED,
                                            context.getAwsRequestId(),
                                            session.getSessionId(),
                                            clientId,
                                            clientSession.getDocAppSubjectId().getValue(),
                                            AuditService.UNKNOWN,
                                            AuditService.UNKNOWN,
                                            AuditService.UNKNOWN,
                                            AuditService.UNKNOWN);
                                    LOG.info(
                                            "Adding DocAppCredential to DB with Subject: {}",
                                            clientSession.getDocAppSubjectId());
                                    dynamoDocAppService.addDocAppCredential(
                                            clientSession.getDocAppSubjectId().getValue(),
                                            credential);

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

                                } catch (UnsuccesfulCredentialResponseException e) {
                                    auditService.submitAuditEvent(
                                            DocAppAuditableEvent
                                                    .DOC_APP_UNSUCCESSFUL_CREDENTIAL_RESPONSE_RECEIVED,
                                            context.getAwsRequestId(),
                                            session.getSessionId(),
                                            clientId,
                                            clientSession.getDocAppSubjectId().getValue(),
                                            AuditService.UNKNOWN,
                                            AuditService.UNKNOWN,
                                            AuditService.UNKNOWN,
                                            AuditService.UNKNOWN);
                                    throw e;
                                }
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

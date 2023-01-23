package uk.gov.di.authentication.app.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.auth.verifier.InvalidClientException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.app.domain.DocAppAuditableEvent;
import uk.gov.di.authentication.app.exception.DocAppCallbackException;
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
import uk.gov.di.authentication.shared.services.DynamoClientService;
import uk.gov.di.authentication.shared.services.JwksService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.shared.services.SessionService;

import java.net.URI;
import java.util.Map;

import static com.nimbusds.oauth2.sdk.http.HTTPRequest.Method.POST;
import static java.lang.String.format;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.ConstructUriHelper.buildURI;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.CLIENT_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.CLIENT_SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.GOVUK_SIGNIN_JOURNEY_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachSessionIdToLogs;

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
    private final DynamoClientService dynamoClientService;
    private final CookieHelper cookieHelper;
    protected final Json objectMapper = SerializationService.getInstance();
    private static final String REDIRECT_PATH = "doc-app-callback";
    private static final String ERROR = "error";
    private static final String ERROR_DESCRIPTION = "error_description";

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
            DynamoDocAppService dynamoDocAppService,
            CookieHelper cookieHelper,
            DynamoClientService dynamoClientService) {
        this.configurationService = configurationService;
        this.authorisationService = responseService;
        this.tokenService = tokenService;
        this.sessionService = sessionService;
        this.clientSessionService = clientSessionService;
        this.auditService = auditService;
        this.dynamoDocAppService = dynamoDocAppService;
        this.cookieHelper = cookieHelper;
        this.dynamoClientService = dynamoClientService;
    }

    public DocAppCallbackHandler(ConfigurationService configurationService) {
        var kmsConnectionService = new KmsConnectionService(configurationService);
        this.configurationService = configurationService;
        this.authorisationService =
                new DocAppAuthorisationService(
                        configurationService,
                        new RedisConnectionService(configurationService),
                        kmsConnectionService,
                        new JwksService(configurationService, kmsConnectionService));
        this.tokenService = new DocAppCriService(configurationService, kmsConnectionService);
        this.sessionService = new SessionService(configurationService);
        this.clientSessionService = new ClientSessionService(configurationService);
        this.auditService = new AuditService(configurationService);
        this.dynamoDocAppService = new DynamoDocAppService(configurationService);
        this.cookieHelper = new CookieHelper();
        this.dynamoClientService = new DynamoClientService(configurationService);
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
        LOG.info("Request received to DocAppCallbackHandler");
        try {
            if (isCustomDocAppClaimEnabledAndCustomErrorPresent(input.getQueryStringParameters())) {
                var clientId = configurationService.getDocAppRPClientId();
                var clientRegistry =
                        dynamoClientService
                                .getClient(clientId)
                                .orElseThrow(
                                        () ->
                                                new InvalidClientException(
                                                        format(
                                                                "No client found with clientId: %s",
                                                                clientId)));
                var redirectUrl = clientRegistry.getRedirectUrls().get(0);
                var errorObject =
                        new ErrorObject(OAuth2Error.ACCESS_DENIED_CODE, "Missing Context");
                var errorResponse =
                        new AuthenticationErrorResponse(
                                URI.create(redirectUrl), errorObject, null, null);
                return generateApiGatewayProxyResponse(
                        302,
                        "",
                        Map.of(ResponseHeaders.LOCATION, errorResponse.toURI().toString()),
                        null);
            }
            var sessionCookiesIds =
                    cookieHelper
                            .parseSessionCookie(input.getHeaders())
                            .orElseThrow(
                                    () -> {
                                        throw new DocAppCallbackException(
                                                "No session cookie present");
                                    });
            var session =
                    sessionService
                            .readSessionFromRedis(sessionCookiesIds.getSessionId())
                            .orElseThrow(
                                    () -> {
                                        throw new DocAppCallbackException("Session not found");
                                    });
            attachSessionIdToLogs(session);
            var clientSessionId = sessionCookiesIds.getClientSessionId();
            var clientSession =
                    clientSessionService
                            .getClientSession(clientSessionId)
                            .orElseThrow(
                                    () -> {
                                        throw new DocAppCallbackException(
                                                "ClientSession not found");
                                    });
            attachLogFieldToLogs(CLIENT_SESSION_ID, clientSessionId);
            attachLogFieldToLogs(GOVUK_SIGNIN_JOURNEY_ID, clientSessionId);

            var authenticationRequest =
                    AuthenticationRequest.parse(clientSession.getAuthRequestParams());

            var clientId = authenticationRequest.getClientID().getValue();
            attachLogFieldToLogs(CLIENT_ID, clientId);

            var errorObject =
                    authorisationService.validateResponse(
                            input.getQueryStringParameters(), session.getSessionId());

            if (errorObject.isPresent()) {
                return generateAuthenticationErrorResponse(
                        authenticationRequest, errorObject.get());
            }

            auditService.submitAuditEvent(
                    DocAppAuditableEvent.DOC_APP_AUTHORISATION_RESPONSE_RECEIVED,
                    clientSessionId,
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
                LOG.info("TokenResponse was successful");
                auditService.submitAuditEvent(
                        DocAppAuditableEvent.DOC_APP_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED,
                        clientSessionId,
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
                        DocAppAuditableEvent.DOC_APP_UNSUCCESSFUL_TOKEN_RESPONSE_RECEIVED,
                        clientSessionId,
                        session.getSessionId(),
                        clientId,
                        clientSession.getDocAppSubjectId().getValue(),
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN);
                return redirectToFrontendErrorPage();
            }

            try {
                var criDataURI =
                        buildURI(
                                configurationService.getDocAppBackendURI().toString(),
                                configurationService.getDocAppCriDataEndpoint());

                var request = new HTTPRequest(POST, criDataURI);
                request.setAuthorization(
                        tokenResponse
                                .toSuccessResponse()
                                .getTokens()
                                .getAccessToken()
                                .toAuthorizationHeader());
                var credential =
                        tokenService.sendCriDataRequest(
                                request, clientSession.getDocAppSubjectId().getValue());
                auditService.submitAuditEvent(
                        DocAppAuditableEvent.DOC_APP_SUCCESSFUL_CREDENTIAL_RESPONSE_RECEIVED,
                        clientSessionId,
                        session.getSessionId(),
                        clientId,
                        clientSession.getDocAppSubjectId().getValue(),
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN);
                LOG.info("Adding DocAppCredential to dynamo");
                dynamoDocAppService.addDocAppCredential(
                        clientSession.getDocAppSubjectId().getValue(), credential);

                var redirectURI =
                        ConstructUriHelper.buildURI(
                                configurationService.getLoginURI().toString(), REDIRECT_PATH);
                LOG.info("Redirecting to frontend");
                return generateApiGatewayProxyResponse(
                        302, "", Map.of(ResponseHeaders.LOCATION, redirectURI.toString()), null);

            } catch (UnsuccesfulCredentialResponseException e) {
                auditService.submitAuditEvent(
                        DocAppAuditableEvent.DOC_APP_UNSUCCESSFUL_CREDENTIAL_RESPONSE_RECEIVED,
                        clientSessionId,
                        session.getSessionId(),
                        clientId,
                        clientSession.getDocAppSubjectId().getValue(),
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN);
                LOG.error("Doc App sendCriDataRequest was not successful: {}", e.getMessage());
                return redirectToFrontendErrorPage();
            }
        } catch (DocAppCallbackException e) {
            LOG.warn(e.getMessage());
            return redirectToFrontendErrorPage();
        } catch (ParseException e) {
            LOG.info("Cannot retrieve auth request params from client session id");
            return redirectToFrontendErrorPage();
        } catch (InvalidClientException e) {
            LOG.error("Client not found with given clientID", e);
            throw new RuntimeException(e);
        }
    }

    private APIGatewayProxyResponseEvent generateAuthenticationErrorResponse(
            AuthenticationRequest authenticationRequest, ErrorObject errorObject) {
        LOG.warn(
                "Error in Doc App AuthorisationResponse. ErrorCode: {}. ErrorDescription: {}",
                errorObject.getCode(),
                errorObject.getDescription());
        var errorResponse =
                new AuthenticationErrorResponse(
                        authenticationRequest.getRedirectionURI(),
                        errorObject,
                        authenticationRequest.getState(),
                        authenticationRequest.getResponseMode());
        return generateApiGatewayProxyResponse(
                302, "", Map.of(ResponseHeaders.LOCATION, errorResponse.toURI().toString()), null);
    }

    private APIGatewayProxyResponseEvent redirectToFrontendErrorPage() {
        LOG.info("Redirecting to frontend error page");
        return generateApiGatewayProxyResponse(
                302,
                "",
                Map.of(
                        ResponseHeaders.LOCATION,
                        ConstructUriHelper.buildURI(
                                        configurationService.getLoginURI().toString(), ERROR)
                                .toString()),
                null);
    }

    private boolean isCustomDocAppClaimEnabledAndCustomErrorPresent(
            Map<String, String> queryStringParameters) {
        return configurationService.isCustomDocAppClaimEnabled()
                && queryStringParameters.containsKey(ERROR)
                && queryStringParameters.get(ERROR).equals(OAuth2Error.ACCESS_DENIED.getCode())
                && queryStringParameters.get(ERROR_DESCRIPTION).equals("Missing Context");
    }
}

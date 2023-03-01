package uk.gov.di.authentication.app.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.State;
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
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.JwksService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.shared.services.SessionService;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import static com.nimbusds.oauth2.sdk.http.HTTPRequest.Method.POST;
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
    private final CloudwatchMetricsService cloudwatchMetricsService;
    private final CookieHelper cookieHelper;
    protected final Json objectMapper = SerializationService.getInstance();
    private static final String REDIRECT_PATH = "doc-app-callback";

    private static final String ERROR_PAGE_REDIRECT_PATH = "error";

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
            CloudwatchMetricsService cloudwatchMetricsService) {
        this.configurationService = configurationService;
        this.authorisationService = responseService;
        this.tokenService = tokenService;
        this.sessionService = sessionService;
        this.clientSessionService = clientSessionService;
        this.auditService = auditService;
        this.dynamoDocAppService = dynamoDocAppService;
        this.cookieHelper = cookieHelper;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
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
        this.cloudwatchMetricsService = new CloudwatchMetricsService(configurationService);
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
            var sessionCookiesIds =
                    cookieHelper.parseSessionCookie(input.getHeaders()).orElse(null);
            if (Objects.isNull(sessionCookiesIds)) {
                LOG.warn("No session cookie present. Attempt to find session using state");
                return generateNoSessionErrorResponse(input.getQueryStringParameters());
            }
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
                        authenticationRequest,
                        errorObject.get(),
                        false,
                        clientId,
                        clientSessionId,
                        session.getSessionId(),
                        clientSession.getDocAppSubjectId().getValue());
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
                incrementDocAppCallbackErrorCounter(false, "UnsuccessfulTokenResponse");
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
                var dimensions =
                        new HashMap<>(
                                Map.of(
                                        "Environment", configurationService.getEnvironment(),
                                        "Successful", Boolean.toString(true)));
                cloudwatchMetricsService.incrementCounter("DocAppCallback", dimensions);
                return generateApiGatewayProxyResponse(
                        302, "", Map.of(ResponseHeaders.LOCATION, redirectURI.toString()), null);

            } catch (UnsuccesfulCredentialResponseException e) {
                incrementDocAppCallbackErrorCounter(false, "UnsuccessfulCredentialResponse");
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
        }
    }

    private APIGatewayProxyResponseEvent generateAuthenticationErrorResponse(
            AuthenticationRequest authenticationRequest,
            ErrorObject errorObject,
            boolean noSessionErrorResponse,
            String clientId,
            String clientSessionId,
            String sessionId,
            String docAppSubjectId) {
        LOG.warn(
                "Error in Doc App AuthorisationResponse. ErrorCode: {}. ErrorDescription: {}. No Session Error: {}",
                errorObject.getCode(),
                errorObject.getDescription(),
                noSessionErrorResponse);
        incrementDocAppCallbackErrorCounter(noSessionErrorResponse, errorObject.getCode());
        auditService.submitAuditEvent(
                DocAppAuditableEvent.DOC_APP_UNSUCCESSFUL_AUTHORISATION_RESPONSE_RECEIVED,
                clientSessionId,
                sessionId,
                clientId,
                docAppSubjectId,
                AuditService.UNKNOWN,
                AuditService.UNKNOWN,
                AuditService.UNKNOWN,
                AuditService.UNKNOWN);
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
                                        configurationService.getLoginURI().toString(),
                                        ERROR_PAGE_REDIRECT_PATH)
                                .toString()),
                null);
    }

    private APIGatewayProxyResponseEvent generateNoSessionErrorResponse(
            Map<String, String> queryStringParameters)
            throws ParseException, DocAppCallbackException {
        LOG.info(
                "Attempting to generate error response using state. CustomDocAppClaimEnabled: {}",
                configurationService.isCustomDocAppClaimEnabled());
        if (isAccessDeniedErrorAndStatePresent(queryStringParameters)) {
            LOG.info("access_denied error and state param are both present");
            var clientSessionId =
                    authorisationService
                            .getClientSessionIdFromState(
                                    State.parse(queryStringParameters.get("state")))
                            .orElseThrow(
                                    () ->
                                            new DocAppCallbackException(
                                                    "ClientSessionId could not be found using state param"));
            LOG.info("ClientSessionID found using state");
            attachLogFieldToLogs(CLIENT_SESSION_ID, clientSessionId);
            attachLogFieldToLogs(GOVUK_SIGNIN_JOURNEY_ID, clientSessionId);
            var clientSession =
                    clientSessionService
                            .getClientSession(clientSessionId)
                            .orElseThrow(
                                    () ->
                                            new DocAppCallbackException(
                                                    "No client session found with given client sessionId"));
            LOG.info("ClientSession found using clientSessionId");
            var authenticationRequest =
                    AuthenticationRequest.parse(clientSession.getAuthRequestParams());
            var errorDescription =
                    Optional.ofNullable(queryStringParameters.get("error_description"))
                            .orElse(OAuth2Error.ACCESS_DENIED.getDescription());
            var errorObject = new ErrorObject(queryStringParameters.get("error"), errorDescription);
            LOG.info(
                    "ErrorObject created for session cookie not present. Generating error response back to RP");
            return generateAuthenticationErrorResponse(
                    authenticationRequest,
                    errorObject,
                    true,
                    authenticationRequest.getClientID().getValue(),
                    clientSessionId,
                    AuditService.UNKNOWN,
                    clientSession.getDocAppSubjectId().getValue());
        } else {
            LOG.warn(
                    "Session Cookie not present and access_denied or state param missing from error response");
            throw new DocAppCallbackException(
                    "Session Cookie not present and access_denied or state param missing from error response");
        }
    }

    private boolean isAccessDeniedErrorAndStatePresent(Map<String, String> queryStringParameters) {
        return configurationService.isCustomDocAppClaimEnabled()
                && queryStringParameters.containsKey("error")
                && queryStringParameters.get("error").equals(OAuth2Error.ACCESS_DENIED.getCode())
                && queryStringParameters.containsKey("state")
                && Boolean.FALSE.equals(queryStringParameters.get("state").isEmpty());
    }

    private void incrementDocAppCallbackErrorCounter(boolean noSessionError, String error) {
        var dimensions =
                new HashMap<>(
                        Map.of(
                                "Environment", configurationService.getEnvironment(),
                                "NoSessionError", Boolean.toString(noSessionError),
                                "Successful", Boolean.toString(false),
                                "Error", error));

        cloudwatchMetricsService.incrementCounter("DocAppCallback", dimensions);
    }
}

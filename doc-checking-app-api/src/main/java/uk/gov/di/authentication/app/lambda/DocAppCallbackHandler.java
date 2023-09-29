package uk.gov.di.authentication.app.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.authentication.app.domain.DocAppAuditableEvent;
import uk.gov.di.authentication.app.exception.DocAppCallbackException;
import uk.gov.di.authentication.app.services.DocAppAuthorisationService;
import uk.gov.di.authentication.app.services.DocAppCriService;
import uk.gov.di.authentication.app.services.DynamoDocAppService;
import uk.gov.di.authentication.shared.entity.ResponseHeaders;
import uk.gov.di.authentication.shared.exceptions.NoSessionException;
import uk.gov.di.authentication.shared.exceptions.UnsuccessfulCredentialResponseException;
import uk.gov.di.authentication.shared.helpers.ConstructUriHelper;
import uk.gov.di.authentication.shared.helpers.CookieHelper;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthorisationCodeService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.JwksService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;
import uk.gov.di.authentication.shared.services.NoSessionOrchestrationService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.shared.services.SessionService;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import static com.nimbusds.oauth2.sdk.http.HTTPRequest.Method.POST;
import static uk.gov.di.authentication.app.domain.DocAppAuditableEvent.AUTH_CODE_ISSUED;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.ConstructUriHelper.buildURI;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.CLIENT_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.CLIENT_SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.GOVUK_SIGNIN_JOURNEY_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.PERSISTENT_SESSION_ID;
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
    private final NoSessionOrchestrationService noSessionOrchestrationService;
    private final AuthorisationCodeService authorisationCodeService;
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
            AuthorisationCodeService authorisationCodeService,
            CookieHelper cookieHelper,
            CloudwatchMetricsService cloudwatchMetricsService,
            NoSessionOrchestrationService noSessionOrchestrationService) {
        this.configurationService = configurationService;
        this.authorisationService = responseService;
        this.tokenService = tokenService;
        this.sessionService = sessionService;
        this.clientSessionService = clientSessionService;
        this.auditService = auditService;
        this.dynamoDocAppService = dynamoDocAppService;
        this.authorisationCodeService = authorisationCodeService;
        this.cookieHelper = cookieHelper;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
        this.noSessionOrchestrationService = noSessionOrchestrationService;
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
        this.authorisationCodeService = new AuthorisationCodeService(configurationService);
        this.cookieHelper = new CookieHelper();
        this.cloudwatchMetricsService = new CloudwatchMetricsService(configurationService);
        this.noSessionOrchestrationService =
                new NoSessionOrchestrationService(configurationService);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        ThreadContext.clearMap();
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
                var noSessionEntity =
                        noSessionOrchestrationService.generateNoSessionOrchestrationEntity(
                                input.getQueryStringParameters(),
                                configurationService.isCustomDocAppClaimEnabled());
                var authRequest =
                        AuthenticationRequest.parse(
                                noSessionEntity.getClientSession().getAuthRequestParams());
                return generateAuthenticationErrorResponse(
                        authRequest,
                        noSessionEntity.getErrorObject(),
                        true,
                        noSessionEntity.getClientSessionId(),
                        AuditService.UNKNOWN,
                        noSessionEntity.getClientSession().getDocAppSubjectId().getValue());
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
            attachLogFieldToLogs(CLIENT_SESSION_ID, clientSessionId);
            attachLogFieldToLogs(GOVUK_SIGNIN_JOURNEY_ID, clientSessionId);
            var clientSession =
                    clientSessionService
                            .getClientSession(clientSessionId)
                            .orElseThrow(
                                    () -> {
                                        throw new DocAppCallbackException(
                                                "ClientSession not found");
                                    });
            if (Objects.isNull(clientSession.getDocAppSubjectId()))
                throw new DocAppCallbackException("No DocAppSubjectId present in ClientSession");

            var persistentId =
                    PersistentIdHelper.extractPersistentIdFromCookieHeader(input.getHeaders());
            attachLogFieldToLogs(PERSISTENT_SESSION_ID, persistentId);

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
                var criDataEndpoint =
                        configurationService.isDocAppCriV2DataEndpointEnabled()
                                ? configurationService.getDocAppCriV2DataEndpoint()
                                : configurationService.getDocAppCriDataEndpoint();

                var criDataURI =
                        buildURI(
                                configurationService.getDocAppBackendURI().toString(),
                                criDataEndpoint);

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

                if (configurationService.isDocAppDecoupleEnabled()) {
                    var authCode =
                            authorisationCodeService.generateAndSaveAuthorisationCode(
                                    clientSessionId, session.getEmailAddress(), clientSession);

                    var clientRedirectURI = authenticationRequest.getRedirectionURI();
                    var state = authenticationRequest.getState();
                    var responseMode = authenticationRequest.getResponseMode();
                    var authenticationResponse =
                            new AuthenticationSuccessResponse(
                                    clientRedirectURI,
                                    authCode,
                                    null,
                                    null,
                                    state,
                                    null,
                                    responseMode);

                    auditService.submitAuditEvent(
                            AUTH_CODE_ISSUED,
                            clientSessionId,
                            session.getSessionId(),
                            clientId,
                            clientSession.getDocAppSubjectId().getValue(),
                            session.getEmailAddress(),
                            IpAddressHelper.extractIpAddress(input),
                            AuditService.UNKNOWN,
                            AuditService.UNKNOWN);

                    return generateApiGatewayProxyResponse(
                            302,
                            "",
                            Map.of(
                                    ResponseHeaders.LOCATION,
                                    authenticationResponse.toURI().toString()),
                            null);
                }

                return generateApiGatewayProxyResponse(
                        302, "", Map.of(ResponseHeaders.LOCATION, redirectURI.toString()), null);

            } catch (UnsuccessfulCredentialResponseException e) {
                if (e.getHttpCode() == 404) {
                    return generateAuthenticationErrorResponse(
                            authenticationRequest,
                            new ErrorObject(OAuth2Error.ACCESS_DENIED_CODE, "Not found"),
                            false,
                            clientSessionId,
                            session.getSessionId(),
                            clientSession.getDocAppSubjectId().getValue());
                } else {
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
                    LOG.warn("Doc App sendCriDataRequest was not successful: {}", e.getMessage());
                    return redirectToFrontendErrorPage();
                }
            }
        } catch (DocAppCallbackException | NoSessionException e) {
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
                authenticationRequest.getClientID().getValue(),
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

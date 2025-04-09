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
import uk.gov.di.authentication.app.services.DocAppCriService;
import uk.gov.di.authentication.app.services.DynamoDocAppService;
import uk.gov.di.orchestration.audit.TxmaAuditUser;
import uk.gov.di.orchestration.shared.api.AuthFrontend;
import uk.gov.di.orchestration.shared.api.DocAppCriAPI;
import uk.gov.di.orchestration.shared.entity.ResponseHeaders;
import uk.gov.di.orchestration.shared.exceptions.NoSessionException;
import uk.gov.di.orchestration.shared.exceptions.OrchAuthCodeException;
import uk.gov.di.orchestration.shared.exceptions.UnsuccessfulCredentialResponseException;
import uk.gov.di.orchestration.shared.helpers.CookieHelper;
import uk.gov.di.orchestration.shared.helpers.IpAddressHelper;
import uk.gov.di.orchestration.shared.helpers.PersistentIdHelper;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.services.AuditService;
import uk.gov.di.orchestration.shared.services.CloudwatchMetricsService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.DocAppAuthorisationService;
import uk.gov.di.orchestration.shared.services.JwksService;
import uk.gov.di.orchestration.shared.services.KmsConnectionService;
import uk.gov.di.orchestration.shared.services.NoSessionOrchestrationService;
import uk.gov.di.orchestration.shared.services.OrchAuthCodeService;
import uk.gov.di.orchestration.shared.services.OrchClientSessionService;
import uk.gov.di.orchestration.shared.services.OrchSessionService;
import uk.gov.di.orchestration.shared.services.RedirectService;
import uk.gov.di.orchestration.shared.services.RedisConnectionService;
import uk.gov.di.orchestration.shared.services.SerializationService;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import static com.nimbusds.oauth2.sdk.http.HTTPRequest.Method.POST;
import static uk.gov.di.authentication.app.domain.DocAppAuditableEvent.AUTH_CODE_ISSUED;
import static uk.gov.di.orchestration.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.orchestration.shared.helpers.AuditHelper.attachTxmaAuditFieldFromHeaders;
import static uk.gov.di.orchestration.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.CLIENT_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.CLIENT_SESSION_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.GOVUK_SIGNIN_JOURNEY_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.PERSISTENT_SESSION_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachSessionIdToLogs;
import static uk.gov.di.orchestration.shared.services.AuditService.MetadataPair.pair;

public class DocAppCallbackHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(DocAppCallbackHandler.class);
    private final ConfigurationService configurationService;
    private final DocAppAuthorisationService authorisationService;
    private final DocAppCriService tokenService;
    private final OrchClientSessionService orchClientSessionService;
    private final AuditService auditService;
    private final DynamoDocAppService dynamoDocAppService;
    private final CloudwatchMetricsService cloudwatchMetricsService;
    private final NoSessionOrchestrationService noSessionOrchestrationService;
    private final OrchAuthCodeService orchAuthCodeService;
    private final AuthFrontend authFrontend;
    private final DocAppCriAPI docAppCriApi;
    private final OrchSessionService orchSessionService;
    protected final Json objectMapper = SerializationService.getInstance();

    public DocAppCallbackHandler() {
        this(ConfigurationService.getInstance());
    }

    public DocAppCallbackHandler(
            ConfigurationService configurationService,
            DocAppAuthorisationService responseService,
            DocAppCriService tokenService,
            OrchClientSessionService orchClientSessionService,
            AuditService auditService,
            DynamoDocAppService dynamoDocAppService,
            OrchAuthCodeService orchAuthCodeService,
            CloudwatchMetricsService cloudwatchMetricsService,
            NoSessionOrchestrationService noSessionOrchestrationService,
            AuthFrontend authFrontend,
            DocAppCriAPI docAppCriApi,
            OrchSessionService orchSessionService) {
        this.configurationService = configurationService;
        this.authorisationService = responseService;
        this.tokenService = tokenService;
        this.orchClientSessionService = orchClientSessionService;
        this.auditService = auditService;
        this.dynamoDocAppService = dynamoDocAppService;
        this.orchAuthCodeService = orchAuthCodeService;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
        this.noSessionOrchestrationService = noSessionOrchestrationService;
        this.authFrontend = authFrontend;
        this.docAppCriApi = docAppCriApi;
        this.orchSessionService = orchSessionService;
    }

    public DocAppCallbackHandler(ConfigurationService configurationService) {
        var kmsConnectionService = new KmsConnectionService(configurationService);
        this.docAppCriApi = new DocAppCriAPI(configurationService);
        this.configurationService = configurationService;
        this.authorisationService =
                new DocAppAuthorisationService(
                        configurationService,
                        new RedisConnectionService(configurationService),
                        kmsConnectionService,
                        new JwksService(configurationService, kmsConnectionService));
        this.tokenService =
                new DocAppCriService(configurationService, kmsConnectionService, this.docAppCriApi);
        this.orchClientSessionService = new OrchClientSessionService(configurationService);
        this.auditService = new AuditService(configurationService);
        this.dynamoDocAppService = new DynamoDocAppService(configurationService);
        this.orchAuthCodeService = new OrchAuthCodeService(configurationService);
        this.cloudwatchMetricsService = new CloudwatchMetricsService(configurationService);
        this.noSessionOrchestrationService =
                new NoSessionOrchestrationService(configurationService);
        this.authFrontend = new AuthFrontend(configurationService);
        this.orchSessionService = new OrchSessionService(configurationService);
    }

    public DocAppCallbackHandler(
            ConfigurationService configurationService, RedisConnectionService redis) {
        var kmsConnectionService = new KmsConnectionService(configurationService);
        this.docAppCriApi = new DocAppCriAPI(configurationService);
        this.configurationService = configurationService;
        this.authorisationService =
                new DocAppAuthorisationService(
                        configurationService,
                        redis,
                        kmsConnectionService,
                        new JwksService(configurationService, kmsConnectionService));
        this.tokenService =
                new DocAppCriService(configurationService, kmsConnectionService, this.docAppCriApi);
        this.orchClientSessionService = new OrchClientSessionService(configurationService);
        this.auditService = new AuditService(configurationService);
        this.dynamoDocAppService = new DynamoDocAppService(configurationService);
        this.orchAuthCodeService = new OrchAuthCodeService(configurationService);
        this.cloudwatchMetricsService = new CloudwatchMetricsService(configurationService);
        this.noSessionOrchestrationService =
                new NoSessionOrchestrationService(configurationService, redis);
        this.authFrontend = new AuthFrontend(configurationService);
        this.orchSessionService = new OrchSessionService(configurationService);
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
        attachTxmaAuditFieldFromHeaders(input.getHeaders());
        try {
            var sessionCookiesIds =
                    CookieHelper.parseSessionCookie(input.getHeaders()).orElse(null);

            if (Objects.isNull(sessionCookiesIds)) {
                LOG.warn("No session cookie present. Attempt to find session using state");
                var noSessionEntity =
                        noSessionOrchestrationService.generateNoSessionOrchestrationEntity(
                                input.getQueryStringParameters());
                var authRequest =
                        AuthenticationRequest.parse(
                                noSessionEntity.getClientSession().getAuthRequestParams());
                return generateAuthenticationErrorResponse(
                        authRequest,
                        noSessionEntity.getErrorObject(),
                        true,
                        TxmaAuditUser.user()
                                .withGovukSigninJourneyId(noSessionEntity.getClientSessionId())
                                .withUserId(
                                        noSessionEntity.getClientSession().getDocAppSubjectId()));
            }
            var sessionId = sessionCookiesIds.getSessionId();
            var clientSessionId = sessionCookiesIds.getClientSessionId();

            var orchSession =
                    orchSessionService
                            .getSession(sessionId)
                            .orElseThrow(
                                    () -> new DocAppCallbackException("Orch Session not found"));

            attachSessionIdToLogs(sessionId);
            attachLogFieldToLogs(CLIENT_SESSION_ID, clientSessionId);
            attachLogFieldToLogs(GOVUK_SIGNIN_JOURNEY_ID, clientSessionId);
            var orchClientSession =
                    orchClientSessionService
                            .getClientSession(clientSessionId)
                            .orElseThrow(
                                    () -> new DocAppCallbackException("ClientSession not found"));

            if (Objects.isNull(orchClientSession.getDocAppSubjectId()))
                throw new DocAppCallbackException("No DocAppSubjectId present in ClientSession");

            var persistentId =
                    PersistentIdHelper.extractPersistentIdFromCookieHeader(input.getHeaders());
            attachLogFieldToLogs(PERSISTENT_SESSION_ID, persistentId);

            var authenticationRequest =
                    AuthenticationRequest.parse(orchClientSession.getAuthRequestParams());

            var clientId = authenticationRequest.getClientID().getValue();
            attachLogFieldToLogs(CLIENT_ID, clientId);

            var errorObject =
                    authorisationService.validateResponse(
                            input.getQueryStringParameters(), sessionId);

            var user =
                    TxmaAuditUser.user()
                            .withGovukSigninJourneyId(clientSessionId)
                            .withSessionId(sessionId)
                            .withUserId(orchClientSession.getDocAppSubjectId());

            if (errorObject.isPresent()) {
                return generateAuthenticationErrorResponse(
                        authenticationRequest, errorObject.get(), false, user);
            }

            auditService.submitAuditEvent(
                    DocAppAuditableEvent.DOC_APP_AUTHORISATION_RESPONSE_RECEIVED, clientId, user);

            var tokenRequest =
                    tokenService.constructTokenRequest(
                            input.getQueryStringParameters().get("code"));
            var tokenResponse = tokenService.sendTokenRequest(tokenRequest);
            if (tokenResponse.indicatesSuccess()) {
                LOG.info("TokenResponse was successful");
                auditService.submitAuditEvent(
                        DocAppAuditableEvent.DOC_APP_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED,
                        clientId,
                        user);
            } else {
                LOG.error(
                        "Doc App TokenResponse was not successful: {}",
                        tokenResponse.toErrorResponse().toJSONObject());
                incrementDocAppCallbackErrorCounter(false, "UnsuccessfulTokenResponse");
                auditService.submitAuditEvent(
                        DocAppAuditableEvent.DOC_APP_UNSUCCESSFUL_TOKEN_RESPONSE_RECEIVED,
                        clientId,
                        user);
                return RedirectService.redirectToFrontendErrorPage(authFrontend.errorURI());
            }

            try {
                var criDataURI = docAppCriApi.criDataURI();

                var request = new HTTPRequest(POST, criDataURI);
                request.setAuthorization(
                        tokenResponse
                                .toSuccessResponse()
                                .getTokens()
                                .getAccessToken()
                                .toAuthorizationHeader());
                var credential =
                        tokenService.sendCriDataRequest(
                                request, orchClientSession.getDocAppSubjectId());
                auditService.submitAuditEvent(
                        DocAppAuditableEvent.DOC_APP_SUCCESSFUL_CREDENTIAL_RESPONSE_RECEIVED,
                        clientId,
                        user);
                LOG.info("Adding DocAppCredential to dynamo");
                dynamoDocAppService.addDocAppCredential(
                        orchClientSession.getDocAppSubjectId(), credential);

                LOG.info("Redirecting to frontend");
                var dimensions =
                        new HashMap<>(
                                Map.of(
                                        "Environment", configurationService.getEnvironment(),
                                        "Successful", Boolean.toString(true)));
                cloudwatchMetricsService.incrementCounter("DocAppCallback", dimensions);

                var authCode =
                        orchAuthCodeService.generateAndSaveAuthorisationCode(
                                clientId, clientSessionId, null, null);

                var authenticationResponse =
                        new AuthenticationSuccessResponse(
                                authenticationRequest.getRedirectionURI(),
                                authCode,
                                null,
                                null,
                                authenticationRequest.getState(),
                                null,
                                authenticationRequest.getResponseMode());

                var metadataPairs = new ArrayList<AuditService.MetadataPair>();
                metadataPairs.add(pair("internalSubjectId", AuditService.UNKNOWN));
                metadataPairs.add(pair("isNewAccount", orchSession.getIsNewAccount()));
                metadataPairs.add(pair("rpPairwiseId", AuditService.UNKNOWN));
                metadataPairs.add(pair("authCode", authCode));
                if (authenticationRequest.getNonce() != null) {
                    metadataPairs.add(pair("nonce", authenticationRequest.getNonce().getValue()));
                }

                auditService.submitAuditEvent(
                        AUTH_CODE_ISSUED,
                        clientId,
                        user.withIpAddress(IpAddressHelper.extractIpAddress(input)),
                        metadataPairs.toArray(AuditService.MetadataPair[]::new));

                return generateApiGatewayProxyResponse(
                        302,
                        "",
                        Map.of(ResponseHeaders.LOCATION, authenticationResponse.toURI().toString()),
                        null);

            } catch (UnsuccessfulCredentialResponseException e) {
                if (e.getHttpCode() == 404) {
                    return generateAuthenticationErrorResponse(
                            authenticationRequest,
                            new ErrorObject(OAuth2Error.ACCESS_DENIED_CODE, "Not found"),
                            false,
                            user);
                } else {
                    incrementDocAppCallbackErrorCounter(false, "UnsuccessfulCredentialResponse");
                    auditService.submitAuditEvent(
                            DocAppAuditableEvent.DOC_APP_UNSUCCESSFUL_CREDENTIAL_RESPONSE_RECEIVED,
                            clientId,
                            user);
                    LOG.warn("Doc App sendCriDataRequest was not successful: {}", e.getMessage());
                    return RedirectService.redirectToFrontendErrorPage(authFrontend.errorURI());
                }
            }
        } catch (DocAppCallbackException | NoSessionException | OrchAuthCodeException e) {
            LOG.warn(e.getMessage());
            return RedirectService.redirectToFrontendErrorPage(authFrontend.errorURI());
        } catch (ParseException e) {
            LOG.info("Cannot retrieve auth request params from client session id");
            return RedirectService.redirectToFrontendErrorPage(authFrontend.errorURI());
        }
    }

    private APIGatewayProxyResponseEvent generateAuthenticationErrorResponse(
            AuthenticationRequest authenticationRequest,
            ErrorObject errorObject,
            boolean noSessionErrorResponse,
            TxmaAuditUser user) {
        LOG.warn(
                "Error in Doc App AuthorisationResponse. ErrorCode: {}. ErrorDescription: {}. No Session Error: {}",
                errorObject.getCode(),
                errorObject.getDescription(),
                noSessionErrorResponse);
        incrementDocAppCallbackErrorCounter(noSessionErrorResponse, errorObject.getCode());
        auditService.submitAuditEvent(
                DocAppAuditableEvent.DOC_APP_UNSUCCESSFUL_AUTHORISATION_RESPONSE_RECEIVED,
                authenticationRequest.getClientID().getValue(),
                user);
        var errorResponse =
                new AuthenticationErrorResponse(
                        authenticationRequest.getRedirectionURI(),
                        errorObject,
                        authenticationRequest.getState(),
                        authenticationRequest.getResponseMode());
        return generateApiGatewayProxyResponse(
                302, "", Map.of(ResponseHeaders.LOCATION, errorResponse.toURI().toString()), null);
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

package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.authentication.oidc.domain.OidcAuditableEvent;
import uk.gov.di.authentication.oidc.entity.AuthCodeResponse;
import uk.gov.di.authentication.oidc.exceptions.ProcessAuthRequestException;
import uk.gov.di.authentication.oidc.services.OrchestrationAuthorizationService;
import uk.gov.di.orchestration.audit.TxmaAuditUser;
import uk.gov.di.orchestration.shared.entity.ClientSession;
import uk.gov.di.orchestration.shared.entity.CredentialTrustLevel;
import uk.gov.di.orchestration.shared.entity.ErrorResponse;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem;
import uk.gov.di.orchestration.shared.entity.Session;
import uk.gov.di.orchestration.shared.entity.VectorOfTrust;
import uk.gov.di.orchestration.shared.exceptions.ClientNotFoundException;
import uk.gov.di.orchestration.shared.exceptions.UserNotFoundException;
import uk.gov.di.orchestration.shared.helpers.IpAddressHelper;
import uk.gov.di.orchestration.shared.helpers.PersistentIdHelper;
import uk.gov.di.orchestration.shared.serialization.Json.JsonException;
import uk.gov.di.orchestration.shared.services.AuditService;
import uk.gov.di.orchestration.shared.services.AuthCodeResponseGenerationService;
import uk.gov.di.orchestration.shared.services.AuthorisationCodeService;
import uk.gov.di.orchestration.shared.services.ClientSessionService;
import uk.gov.di.orchestration.shared.services.CloudwatchMetricsService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.DynamoClientService;
import uk.gov.di.orchestration.shared.services.DynamoService;
import uk.gov.di.orchestration.shared.services.OrchClientSessionService;
import uk.gov.di.orchestration.shared.services.OrchSessionService;
import uk.gov.di.orchestration.shared.services.RedisConnectionService;
import uk.gov.di.orchestration.shared.services.SessionService;

import java.net.URI;
import java.util.ArrayList;
import java.util.Objects;
import java.util.Optional;

import static java.util.Objects.isNull;
import static uk.gov.di.orchestration.shared.conditions.DocAppUserHelper.isDocCheckingAppUserWithSubjectId;
import static uk.gov.di.orchestration.shared.domain.RequestHeaders.CLIENT_SESSION_ID_HEADER;
import static uk.gov.di.orchestration.shared.domain.RequestHeaders.SESSION_ID_HEADER;
import static uk.gov.di.orchestration.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.orchestration.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.orchestration.shared.helpers.InstrumentationHelper.addAnnotation;
import static uk.gov.di.orchestration.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.CLIENT_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.CLIENT_SESSION_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.GOVUK_SIGNIN_JOURNEY_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.PERSISTENT_SESSION_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachOrchSessionIdToLogs;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachSessionIdToLogs;
import static uk.gov.di.orchestration.shared.helpers.RequestHeaderHelper.getHeaderValueFromHeaders;
import static uk.gov.di.orchestration.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.orchestration.shared.utils.ClientSessionMigrationUtils.logIfClientSessionsAreNotEqual;

public class AuthCodeHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(AuthCodeHandler.class);

    private final SessionService sessionService;
    private final OrchSessionService orchSessionService;
    private final AuthCodeResponseGenerationService authCodeResponseService;
    private final AuthorisationCodeService authorisationCodeService;
    private final OrchestrationAuthorizationService orchestrationAuthorizationService;
    private final ClientSessionService clientSessionService;
    private final OrchClientSessionService orchClientSessionService;
    private final AuditService auditService;
    private final CloudwatchMetricsService cloudwatchMetricsService;
    private final ConfigurationService configurationService;
    private final DynamoService dynamoService;
    private final DynamoClientService dynamoClientService;

    public AuthCodeHandler(
            SessionService sessionService,
            OrchSessionService orchSessionService,
            AuthCodeResponseGenerationService authCodeResponseService,
            AuthorisationCodeService authorisationCodeService,
            OrchestrationAuthorizationService orchestrationAuthorizationService,
            ClientSessionService clientSessionService,
            OrchClientSessionService orchClientSessionService,
            AuditService auditService,
            CloudwatchMetricsService cloudwatchMetricsService,
            ConfigurationService configurationService,
            DynamoService dynamoService,
            DynamoClientService dynamoClientService) {
        this.sessionService = sessionService;
        this.orchSessionService = orchSessionService;
        this.authCodeResponseService = authCodeResponseService;
        this.authorisationCodeService = authorisationCodeService;
        this.orchestrationAuthorizationService = orchestrationAuthorizationService;
        this.clientSessionService = clientSessionService;
        this.orchClientSessionService = orchClientSessionService;
        this.auditService = auditService;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
        this.configurationService = configurationService;
        this.dynamoService = dynamoService;
        this.dynamoClientService = dynamoClientService;
    }

    public AuthCodeHandler(ConfigurationService configurationService) {
        sessionService = new SessionService(configurationService);
        orchSessionService = new OrchSessionService(configurationService);
        authorisationCodeService = new AuthorisationCodeService(configurationService);
        orchestrationAuthorizationService =
                new OrchestrationAuthorizationService(configurationService);
        clientSessionService = new ClientSessionService(configurationService);
        this.orchClientSessionService = new OrchClientSessionService(configurationService);
        auditService = new AuditService(configurationService);
        cloudwatchMetricsService = new CloudwatchMetricsService();
        this.configurationService = configurationService;
        dynamoService = new DynamoService(configurationService);
        dynamoClientService = new DynamoClientService(configurationService);
        authCodeResponseService =
                new AuthCodeResponseGenerationService(configurationService, dynamoService);
    }

    public AuthCodeHandler(
            ConfigurationService configurationService, RedisConnectionService redis) {
        sessionService = new SessionService(configurationService, redis);
        orchSessionService = new OrchSessionService(configurationService);
        authorisationCodeService = new AuthorisationCodeService(configurationService);
        orchestrationAuthorizationService =
                new OrchestrationAuthorizationService(configurationService);
        clientSessionService = new ClientSessionService(configurationService, redis);
        this.orchClientSessionService = new OrchClientSessionService(configurationService);
        auditService = new AuditService(configurationService);
        cloudwatchMetricsService = new CloudwatchMetricsService();
        this.configurationService = configurationService;
        dynamoService = new DynamoService(configurationService);
        dynamoClientService = new DynamoClientService(configurationService);
        authCodeResponseService =
                new AuthCodeResponseGenerationService(configurationService, dynamoService);
    }

    public AuthCodeHandler() {
        this(ConfigurationService.getInstance());
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        ThreadContext.clearMap();
        return segmentedFunctionCall(
                "oidc-api::" + getClass().getSimpleName(),
                () -> authCodeRequestHandler(input, context));
    }

    public APIGatewayProxyResponseEvent authCodeRequestHandler(
            APIGatewayProxyRequestEvent input, Context context) {
        String sessionId;
        Session session;
        OrchSessionItem orchSession;
        String clientSessionId;
        try {
            sessionId =
                    getHeaderValueFromHeaders(
                            input.getHeaders(),
                            SESSION_ID_HEADER,
                            configurationService.getHeadersCaseInsensitive());
            if (sessionId == null) {
                return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1000);
            }
            session = sessionService.getSession(sessionId).orElse(null);
            orchSession = orchSessionService.getSession(sessionId).orElse(null);
            clientSessionId =
                    getHeaderValueFromHeaders(
                            input.getHeaders(),
                            CLIENT_SESSION_ID_HEADER,
                            configurationService.getHeadersCaseInsensitive());
            validateSessions(session, orchSession, clientSessionId);
        } catch (ProcessAuthRequestException e) {
            return generateApiGatewayProxyErrorResponse(e.getStatusCode(), e.getErrorResponse());
        }

        attachSessionIdToLogs(sessionId);
        attachOrchSessionIdToLogs(orchSession.getSessionId());
        attachLogFieldToLogs(CLIENT_SESSION_ID, clientSessionId);
        attachLogFieldToLogs(GOVUK_SIGNIN_JOURNEY_ID, clientSessionId);

        LOG.info("Processing request");

        AuthenticationRequest authenticationRequest = null;
        ClientSession clientSession;
        ClientID clientID;
        AuthorizationCode authCode;
        AuthenticationSuccessResponse authenticationResponse;
        try {
            clientSession = getClientSession(input);
            authenticationRequest =
                    AuthenticationRequest.parse(clientSession.getAuthRequestParams());

            clientID = authenticationRequest.getClientID();
            attachLogFieldToLogs(CLIENT_ID, clientID.getValue());
            attachLogFieldToLogs(
                    PERSISTENT_SESSION_ID,
                    PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders()));
            addAnnotation(
                    "client_id",
                    String.valueOf(clientSession.getAuthRequestParams().get("client_id")));

            var redirectUri = authenticationRequest.getRedirectionURI();
            var state = authenticationRequest.getState();
            authCode =
                    generateAuthCode(
                            clientID,
                            redirectUri,
                            clientSession,
                            clientSessionId,
                            session,
                            orchSession);
            authenticationResponse =
                    orchestrationAuthorizationService.generateSuccessfulAuthResponse(
                            authenticationRequest, authCode, redirectUri, state);
        } catch (ProcessAuthRequestException e) {
            return generateApiGatewayProxyErrorResponse(e.getStatusCode(), e.getErrorResponse());
        } catch (ClientNotFoundException e) {
            return processClientNotFoundException(authenticationRequest);
        } catch (ParseException e) {
            return processParseException(e);
        }

        LOG.info("Successfully processed request");

        try {
            var isTestJourney =
                    orchestrationAuthorizationService.isTestJourney(
                            clientID, session.getEmailAddress());
            var docAppJourney = isDocCheckingAppUserWithSubjectId(clientSession);
            var dimensions =
                    authCodeResponseService.getDimensions(
                            orchSession,
                            clientSession,
                            clientID.getValue(),
                            isTestJourney,
                            docAppJourney);

            var subjectId = AuditService.UNKNOWN;
            var rpPairwiseId = AuditService.UNKNOWN;
            String internalCommonSubjectId;
            if (docAppJourney) {
                LOG.info("Session not saved for DocCheckingAppUser");
                internalCommonSubjectId = clientSession.getDocAppSubjectId().getValue();
            } else {
                authCodeResponseService.processVectorOfTrust(clientSession, dimensions);
                internalCommonSubjectId = orchSession.getInternalCommonSubjectId();
                subjectId = authCodeResponseService.getSubjectId(session);
                rpPairwiseId =
                        authCodeResponseService.getRpPairwiseId(
                                session, clientID, dynamoClientService);
            }

            var metadataPairs = new ArrayList<AuditService.MetadataPair>();
            metadataPairs.add(pair("internalSubjectId", subjectId));
            metadataPairs.add(pair("isNewAccount", orchSession.getIsNewAccount()));
            metadataPairs.add(pair("rpPairwiseId", rpPairwiseId));
            metadataPairs.add(pair("authCode", authCode));
            if (authenticationRequest.getNonce() != null) {
                metadataPairs.add(pair("nonce", authenticationRequest.getNonce().getValue()));
            }

            auditService.submitAuditEvent(
                    OidcAuditableEvent.AUTH_CODE_ISSUED,
                    clientID.getValue(),
                    TxmaAuditUser.user()
                            .withGovukSigninJourneyId(clientSessionId)
                            .withSessionId(sessionId)
                            .withUserId(internalCommonSubjectId)
                            .withEmail(
                                    Optional.ofNullable(session.getEmailAddress())
                                            .orElse(AuditService.UNKNOWN))
                            .withIpAddress(IpAddressHelper.extractIpAddress(input))
                            .withPersistentSessionId(
                                    PersistentIdHelper.extractPersistentIdFromHeaders(
                                            input.getHeaders())),
                    metadataPairs.toArray(AuditService.MetadataPair[]::new));

            cloudwatchMetricsService.incrementCounter("SignIn", dimensions);

            cloudwatchMetricsService.incrementSignInByClient(
                    orchSession.getIsNewAccount(),
                    clientID.getValue(),
                    clientSession.getClientName(),
                    isTestJourney);
            authCodeResponseService.saveSession(
                    docAppJourney,
                    sessionService,
                    session,
                    sessionId,
                    orchSessionService,
                    orchSession);

            LOG.info("Generating successful auth code response");
            return generateApiGatewayProxyResponse(
                    200,
                    new uk.gov.di.orchestration.entity.AuthCodeResponse(
                            authenticationResponse.toURI().toString()));
        } catch (ClientNotFoundException e) {
            return processClientNotFoundException(authenticationRequest);
        } catch (UserNotFoundException e) {
            LOG.error(e);
            throw new RuntimeException(e);
        } catch (JsonException e) {
            throw new RuntimeException(e);
        }
    }

    private void validateSessions(
            Session session, OrchSessionItem orchSession, String clientSessionId)
            throws ProcessAuthRequestException {
        if (Objects.isNull(session)) {
            throw new ProcessAuthRequestException(400, ErrorResponse.ERROR_1000);
        }
        if (Objects.isNull(orchSession)) {
            throw new ProcessAuthRequestException(400, ErrorResponse.ERROR_1000);
        }
        if (Objects.isNull(clientSessionId)) {
            throw new ProcessAuthRequestException(400, ErrorResponse.ERROR_1018);
        }
    }

    private ClientSession getClientSession(APIGatewayProxyRequestEvent input)
            throws ProcessAuthRequestException {
        var clientSession =
                clientSessionService
                        .getClientSessionFromRequestHeaders(input.getHeaders())
                        .orElse(null);
        var orchClientSession =
                orchClientSessionService
                        .getClientSessionFromRequestHeaders(input.getHeaders())
                        .orElse(null);
        logIfClientSessionsAreNotEqual(clientSession, orchClientSession);
        if (Objects.isNull(clientSession)) {
            LOG.info("ClientSession not found");
            throw new ProcessAuthRequestException(400, ErrorResponse.ERROR_1018);
        }
        return clientSession;
    }

    private APIGatewayProxyResponseEvent generateResponse(
            int httpStatus, AuthCodeResponse response) {
        try {
            LOG.info("Generating successful auth code response");
            return generateApiGatewayProxyResponse(httpStatus, response);
        } catch (JsonException e) {
            throw new RuntimeException(e);
        }
    }

    private APIGatewayProxyResponseEvent processParseException(ParseException e) {
        if (e.getRedirectionURI() == null) {
            LOG.warn(
                    "Authentication request could not be parsed: redirect URI or Client ID is missing from auth request",
                    e);
            throw new RuntimeException("Redirect URI or Client ID is missing from auth request", e);
        }
        AuthenticationErrorResponse errorResponse =
                orchestrationAuthorizationService.generateAuthenticationErrorResponse(
                        e.getRedirectionURI(),
                        e.getState(),
                        e.getResponseMode(),
                        e.getErrorObject());
        LOG.warn("Authentication request could not be parsed", e);
        return generateResponse(400, new AuthCodeResponse(errorResponse.toURI().toString()));
    }

    private APIGatewayProxyResponseEvent processClientNotFoundException(
            AuthenticationRequest authenticationRequest) {
        var errorResponse =
                orchestrationAuthorizationService.generateAuthenticationErrorResponse(
                        authenticationRequest,
                        OAuth2Error.INVALID_CLIENT,
                        authenticationRequest.getRedirectionURI(),
                        authenticationRequest.getState());
        return generateResponse(500, new AuthCodeResponse(errorResponse.toURI().toString()));
    }

    private AuthorizationCode generateAuthCode(
            ClientID clientID,
            URI redirectUri,
            ClientSession clientSession,
            String clientSessionId,
            Session session,
            OrchSessionItem orchSession)
            throws ClientNotFoundException, ProcessAuthRequestException {
        if (!orchestrationAuthorizationService.isClientRedirectUriValid(clientID, redirectUri)) {
            throw new ProcessAuthRequestException(400, ErrorResponse.ERROR_1016);
        }
        CredentialTrustLevel lowestRequestedCredentialTrustLevel =
                VectorOfTrust.getLowestCredentialTrustLevel(clientSession.getVtrList());
        if (isNull(session.getCurrentCredentialStrength())
                || lowestRequestedCredentialTrustLevel.compareTo(
                                session.getCurrentCredentialStrength())
                        > 0) {
            session.setCurrentCredentialStrength(lowestRequestedCredentialTrustLevel);
        }
        CredentialTrustLevel currentCredentialStrength = orchSession.getCurrentCredentialStrength();

        if (isNull(currentCredentialStrength)
                || lowestRequestedCredentialTrustLevel.compareTo(currentCredentialStrength) > 0) {
            orchSession.setCurrentCredentialStrength(lowestRequestedCredentialTrustLevel);
        }
        return authorisationCodeService.generateAndSaveAuthorisationCode(
                clientID.getValue(),
                clientSessionId,
                session.getEmailAddress(),
                clientSession,
                orchSession.getAuthTime());
    }
}

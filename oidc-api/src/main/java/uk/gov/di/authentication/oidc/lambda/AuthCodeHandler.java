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
import uk.gov.di.orchestration.shared.services.SessionService;

import java.net.URI;
import java.util.Objects;
import java.util.Optional;

import static java.util.Objects.isNull;
import static uk.gov.di.orchestration.shared.conditions.DocAppUserHelper.isDocCheckingAppUserWithSubjectId;
import static uk.gov.di.orchestration.shared.domain.RequestHeaders.CLIENT_SESSION_ID_HEADER;
import static uk.gov.di.orchestration.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.orchestration.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.orchestration.shared.helpers.InstrumentationHelper.addAnnotation;
import static uk.gov.di.orchestration.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.CLIENT_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.CLIENT_SESSION_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.GOVUK_SIGNIN_JOURNEY_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.PERSISTENT_SESSION_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachSessionIdToLogs;
import static uk.gov.di.orchestration.shared.helpers.RequestHeaderHelper.getHeaderValueFromHeaders;
import static uk.gov.di.orchestration.shared.services.AuditService.MetadataPair.pair;

public class AuthCodeHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(AuthCodeHandler.class);

    private final SessionService sessionService;
    private final AuthCodeResponseGenerationService authCodeResponseService;
    private final AuthorisationCodeService authorisationCodeService;
    private final OrchestrationAuthorizationService orchestrationAuthorizationService;
    private final ClientSessionService clientSessionService;
    private final AuditService auditService;
    private final CloudwatchMetricsService cloudwatchMetricsService;
    private final DynamoService dynamoService;
    private final DynamoClientService dynamoClientService;

    public AuthCodeHandler(
            SessionService sessionService,
            AuthCodeResponseGenerationService authCodeResponseService,
            AuthorisationCodeService authorisationCodeService,
            OrchestrationAuthorizationService orchestrationAuthorizationService,
            ClientSessionService clientSessionService,
            AuditService auditService,
            CloudwatchMetricsService cloudwatchMetricsService,
            DynamoService dynamoService,
            DynamoClientService dynamoClientService) {
        this.sessionService = sessionService;
        this.authCodeResponseService = authCodeResponseService;
        this.authorisationCodeService = authorisationCodeService;
        this.orchestrationAuthorizationService = orchestrationAuthorizationService;
        this.clientSessionService = clientSessionService;
        this.auditService = auditService;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
        this.dynamoService = dynamoService;
        this.dynamoClientService = dynamoClientService;
    }

    public AuthCodeHandler(ConfigurationService configurationService) {
        sessionService = new SessionService(configurationService);
        authorisationCodeService = new AuthorisationCodeService(configurationService);
        orchestrationAuthorizationService =
                new OrchestrationAuthorizationService(configurationService);
        clientSessionService = new ClientSessionService(configurationService);
        auditService = new AuditService(configurationService);
        cloudwatchMetricsService = new CloudwatchMetricsService();
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
        Session session;
        String clientSessionId;
        try {
            session = sessionService.getSessionFromRequestHeaders(input.getHeaders()).orElse(null);
            clientSessionId =
                    getHeaderValueFromHeaders(input.getHeaders(), CLIENT_SESSION_ID_HEADER);
            validateSessions(session, clientSessionId);
        } catch (ProcessAuthRequestException e) {
            return generateApiGatewayProxyErrorResponse(e.getStatusCode(), e.getErrorResponse());
        }

        attachSessionIdToLogs(session);
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
                            clientID, redirectUri, clientSession, clientSessionId, session);
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
                            session,
                            clientSession,
                            clientID.getValue(),
                            isTestJourney,
                            docAppJourney);

            var subjectId = AuditService.UNKNOWN;
            var rpPairwiseId = AuditService.UNKNOWN;
            String internalCommonPairwiseSubjectId;
            if (docAppJourney) {
                LOG.info("Session not saved for DocCheckingAppUser");
                internalCommonPairwiseSubjectId = clientSession.getDocAppSubjectId().getValue();
            } else {
                authCodeResponseService.processVectorOfTrust(clientSession, dimensions);
                internalCommonPairwiseSubjectId = session.getInternalCommonSubjectIdentifier();
                subjectId = authCodeResponseService.getSubjectId(session);
                rpPairwiseId =
                        authCodeResponseService.getRpPairwiseId(
                                session, clientID, dynamoClientService);
            }

            auditService.submitAuditEvent(
                    OidcAuditableEvent.AUTH_CODE_ISSUED,
                    clientID.getValue(),
                    TxmaAuditUser.user()
                            .withGovukSigninJourneyId(clientSessionId)
                            .withSessionId(session.getSessionId())
                            .withUserId(internalCommonPairwiseSubjectId)
                            .withEmail(
                                    Optional.ofNullable(session.getEmailAddress())
                                            .orElse(AuditService.UNKNOWN))
                            .withIpAddress(IpAddressHelper.extractIpAddress(input))
                            .withPersistentSessionId(
                                    PersistentIdHelper.extractPersistentIdFromHeaders(
                                            input.getHeaders())),
                    pair("internalSubjectId", subjectId),
                    pair("isNewAccount", session.isNewAccount()),
                    pair("rpPairwiseId", rpPairwiseId),
                    pair("nonce", authenticationRequest.getNonce()),
                    pair("authCode", authCode));

            cloudwatchMetricsService.incrementCounter("SignIn", dimensions);
            cloudwatchMetricsService.incrementSignInByClient(
                    session.isNewAccount(),
                    clientID.getValue(),
                    clientSession.getClientName(),
                    isTestJourney);

            authCodeResponseService.saveSession(docAppJourney, sessionService, session);

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

    private void validateSessions(Session session, String clientSessionId)
            throws ProcessAuthRequestException {
        if (Objects.isNull(session)) {
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
            Session session)
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
        return authorisationCodeService.generateAndSaveAuthorisationCode(
                clientSessionId, session.getEmailAddress(), clientSession);
    }
}

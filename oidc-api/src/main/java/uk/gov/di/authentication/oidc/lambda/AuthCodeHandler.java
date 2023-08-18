package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.authentication.oidc.domain.OidcAuditableEvent;
import uk.gov.di.authentication.oidc.entity.AuthCodeResponse;
import uk.gov.di.authentication.oidc.services.OrchestrationAuthorizationService;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.LevelOfConfidence;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.shared.exceptions.ClientNotFoundException;
import uk.gov.di.authentication.shared.exceptions.UserNotFoundException;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.serialization.Json.JsonException;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthorisationCodeService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoClientService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.SessionService;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import static java.util.Objects.isNull;
import static uk.gov.di.authentication.shared.conditions.DocAppUserHelper.isDocCheckingAppUserWithSubjectId;
import static uk.gov.di.authentication.shared.domain.RequestHeaders.CLIENT_SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.entity.Session.AccountState.EXISTING;
import static uk.gov.di.authentication.shared.entity.Session.AccountState.EXISTING_DOC_APP_JOURNEY;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.addAnnotation;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.CLIENT_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.CLIENT_SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.GOVUK_SIGNIN_JOURNEY_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.PERSISTENT_SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachSessionIdToLogs;
import static uk.gov.di.authentication.shared.helpers.RequestHeaderHelper.getHeaderValueFromHeaders;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;

public class AuthCodeHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(AuthCodeHandler.class);

    private final SessionService sessionService;
    private final AuthorisationCodeService authorisationCodeService;
    private final OrchestrationAuthorizationService orchestrationAuthorizationService;
    private final ClientSessionService clientSessionService;
    private final AuditService auditService;
    private final CloudwatchMetricsService cloudwatchMetricsService;
    private final ConfigurationService configurationService;
    private final DynamoService dynamoService;
    private final DynamoClientService dynamoClientService;

    public AuthCodeHandler(
            SessionService sessionService,
            AuthorisationCodeService authorisationCodeService,
            OrchestrationAuthorizationService orchestrationAuthorizationService,
            ClientSessionService clientSessionService,
            AuditService auditService,
            CloudwatchMetricsService cloudwatchMetricsService,
            ConfigurationService configurationService,
            DynamoService dynamoService,
            DynamoClientService dynamoClientService) {
        this.sessionService = sessionService;
        this.authorisationCodeService = authorisationCodeService;
        this.orchestrationAuthorizationService = orchestrationAuthorizationService;
        this.clientSessionService = clientSessionService;
        this.auditService = auditService;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
        this.configurationService = configurationService;
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
        this.configurationService = configurationService;
        dynamoService = new DynamoService(configurationService);
        dynamoClientService = new DynamoClientService(configurationService);
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
        Session session =
                sessionService.getSessionFromRequestHeaders(input.getHeaders()).orElse(null);
        if (Objects.isNull(session)) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1000);
        }
        String clientSessionId =
                getHeaderValueFromHeaders(
                        input.getHeaders(),
                        CLIENT_SESSION_ID_HEADER,
                        configurationService.getHeadersCaseInsensitive());

        if (Objects.isNull(clientSessionId)) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1018);
        }
        attachSessionIdToLogs(session);
        attachLogFieldToLogs(CLIENT_SESSION_ID, clientSessionId);
        attachLogFieldToLogs(GOVUK_SIGNIN_JOURNEY_ID, clientSessionId);

        LOG.info("Processing request");

        AuthenticationRequest authenticationRequest;
        ClientSession clientSession;
        try {
            clientSession =
                    clientSessionService
                            .getClientSessionFromRequestHeaders(input.getHeaders())
                            .orElse(null);
            if (Objects.isNull(clientSession)) {
                LOG.info("ClientSession not found");
                return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1018);
            }
            authenticationRequest =
                    AuthenticationRequest.parse(clientSession.getAuthRequestParams());
        } catch (ParseException e) {
            if (e.getRedirectionURI() == null) {
                LOG.warn(
                        "Authentication request could not be parsed: redirect URI or Client ID is missing from auth request",
                        e);
                throw new RuntimeException(
                        "Redirect URI or Client ID is missing from auth request", e);
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

        var clientID = authenticationRequest.getClientID();
        attachLogFieldToLogs(CLIENT_ID, clientID.getValue());
        attachLogFieldToLogs(
                PERSISTENT_SESSION_ID,
                PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders()));
        addAnnotation(
                "client_id", String.valueOf(clientSession.getAuthRequestParams().get("client_id")));

        URI redirectUri = authenticationRequest.getRedirectionURI();
        State state = authenticationRequest.getState();
        try {
            if (!orchestrationAuthorizationService.isClientRedirectUriValid(
                    clientID, redirectUri)) {
                return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1016);
            }
            VectorOfTrust requestedVectorOfTrust = clientSession.getEffectiveVectorOfTrust();
            if (isNull(session.getCurrentCredentialStrength())
                    || requestedVectorOfTrust
                                    .getCredentialTrustLevel()
                                    .compareTo(session.getCurrentCredentialStrength())
                            > 0) {
                session.setCurrentCredentialStrength(
                        requestedVectorOfTrust.getCredentialTrustLevel());
            }
            var authCode =
                    authorisationCodeService.generateAndSaveAuthorisationCode(
                            clientSessionId, session.getEmailAddress(), clientSession);

            var authenticationResponse =
                    orchestrationAuthorizationService.generateSuccessfulAuthResponse(
                            authenticationRequest, authCode, redirectUri, state);

            LOG.info("Successfully processed request");

            var isTestJourney =
                    orchestrationAuthorizationService.isTestJourney(
                            authenticationRequest.getClientID(), session.getEmailAddress());
            var docAppJourney = isDocCheckingAppUserWithSubjectId(clientSession);

            Map<String, String> dimensions =
                    new HashMap<>(
                            Map.of(
                                    "Account",
                                    session.isNewAccount().name(),
                                    "Environment",
                                    configurationService.getEnvironment(),
                                    "Client",
                                    clientID.getValue(),
                                    "IsTest",
                                    Boolean.toString(isTestJourney),
                                    "IsDocApp",
                                    Boolean.toString(docAppJourney),
                                    "ClientName",
                                    clientSession.getClientName()));

            if (Objects.nonNull(session.getVerifiedMfaMethodType())) {
                dimensions.put("MfaMethod", session.getVerifiedMfaMethodType().getValue());
            } else {
                LOG.info(
                        "No mfa method to set. User is either authenticated or signing in from a low level service");
            }

            var internalSubjectId = AuditService.UNKNOWN;
            var rpPairwiseId = AuditService.UNKNOWN;
            String internalCommonPairwiseSubjectId;
            if (docAppJourney) {
                LOG.info("Session not saved for DocCheckingAppUser");
                internalCommonPairwiseSubjectId = clientSession.getDocAppSubjectId().getValue();
            } else {
                var mfaNotRequired =
                        clientSession
                                .getEffectiveVectorOfTrust()
                                .getCredentialTrustLevel()
                                .equals(CredentialTrustLevel.LOW_LEVEL);
                var levelOfConfidence = LevelOfConfidence.NONE.getValue();
                if (clientSession.getEffectiveVectorOfTrust().containsLevelOfConfidence()) {
                    levelOfConfidence =
                            clientSession
                                    .getEffectiveVectorOfTrust()
                                    .getLevelOfConfidence()
                                    .getValue();
                }
                dimensions.put("MfaRequired", mfaNotRequired ? "No" : "Yes");
                dimensions.put("RequestedLevelOfConfidence", levelOfConfidence);
                internalCommonPairwiseSubjectId = session.getInternalCommonSubjectIdentifier();
                var userProfile =
                        dynamoService
                                .getUserProfileByEmailMaybe(session.getEmailAddress())
                                .orElseThrow(
                                        () ->
                                                new UserNotFoundException(
                                                        "Unable to find user with given email address"));
                var client =
                        dynamoClientService
                                .getClient(clientID.getValue())
                                .orElseThrow(
                                        () -> new ClientNotFoundException(clientID.getValue()));
                internalSubjectId =
                        Objects.isNull(session.getEmailAddress())
                                ? AuditService.UNKNOWN
                                : userProfile.getSubjectID();
                rpPairwiseId =
                        ClientSubjectHelper.getSubject(
                                        userProfile,
                                        client,
                                        dynamoService,
                                        configurationService.getInternalSectorUri())
                                .getValue();
            }

            auditService.submitAuditEvent(
                    OidcAuditableEvent.AUTH_CODE_ISSUED,
                    clientSessionId,
                    session.getSessionId(),
                    clientID.getValue(),
                    internalCommonPairwiseSubjectId,
                    Objects.isNull(session.getEmailAddress())
                            ? AuditService.UNKNOWN
                            : session.getEmailAddress(),
                    IpAddressHelper.extractIpAddress(input),
                    AuditService.UNKNOWN,
                    PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders()),
                    pair("internalSubjectId", internalSubjectId),
                    pair("isNewAccount", session.isNewAccount()),
                    pair("rpPairwiseId", rpPairwiseId));

            cloudwatchMetricsService.incrementCounter("SignIn", dimensions);
            cloudwatchMetricsService.incrementSignInByClient(
                    session.isNewAccount(),
                    clientID.getValue(),
                    clientSession.getClientName(),
                    isTestJourney);

            if (docAppJourney) {
                sessionService.save(session.setNewAccount(EXISTING_DOC_APP_JOURNEY));
            } else {
                sessionService.save(session.setAuthenticated(true).setNewAccount(EXISTING));
            }

            return generateResponse(
                    200, new AuthCodeResponse(authenticationResponse.toURI().toString()));
        } catch (ClientNotFoundException e) {
            var errorResponse =
                    orchestrationAuthorizationService.generateAuthenticationErrorResponse(
                            authenticationRequest, OAuth2Error.INVALID_CLIENT, redirectUri, state);
            return generateResponse(500, new AuthCodeResponse(errorResponse.toURI().toString()));
        } catch (UserNotFoundException e) {
            LOG.error(e);
            throw new RuntimeException(e);
        }
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
}

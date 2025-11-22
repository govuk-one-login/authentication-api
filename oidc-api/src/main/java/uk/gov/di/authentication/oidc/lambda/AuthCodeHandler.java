package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.authentication.oidc.domain.OidcAuditableEvent;
import uk.gov.di.authentication.oidc.entity.AuthCodeResponse;
import uk.gov.di.authentication.oidc.exceptions.AuthCodeException;
import uk.gov.di.authentication.oidc.exceptions.ProcessAuthRequestException;
import uk.gov.di.authentication.oidc.services.OrchestrationAuthorizationService;
import uk.gov.di.orchestration.audit.TxmaAuditUser;
import uk.gov.di.orchestration.shared.entity.AuthUserInfoClaims;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.ErrorResponse;
import uk.gov.di.orchestration.shared.entity.OrchClientSessionItem;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem;
import uk.gov.di.orchestration.shared.exceptions.ClientNotFoundException;
import uk.gov.di.orchestration.shared.exceptions.OrchAuthCodeException;
import uk.gov.di.orchestration.shared.helpers.IpAddressHelper;
import uk.gov.di.orchestration.shared.helpers.PersistentIdHelper;
import uk.gov.di.orchestration.shared.serialization.Json.JsonException;
import uk.gov.di.orchestration.shared.services.AuditService;
import uk.gov.di.orchestration.shared.services.AuthCodeResponseGenerationService;
import uk.gov.di.orchestration.shared.services.AuthenticationUserInfoStorageService;
import uk.gov.di.orchestration.shared.services.CloudwatchMetricsService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.DynamoClientService;
import uk.gov.di.orchestration.shared.services.OrchAuthCodeService;
import uk.gov.di.orchestration.shared.services.OrchClientSessionService;
import uk.gov.di.orchestration.shared.services.OrchSessionService;

import java.net.URI;
import java.util.ArrayList;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import static uk.gov.di.orchestration.shared.conditions.DocAppUserHelper.isDocCheckingAppUserWithSubjectId;
import static uk.gov.di.orchestration.shared.domain.RequestHeaders.CLIENT_SESSION_ID_HEADER;
import static uk.gov.di.orchestration.shared.domain.RequestHeaders.SESSION_ID_HEADER;
import static uk.gov.di.orchestration.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.orchestration.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.AWS_REQUEST_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.CLIENT_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.CLIENT_SESSION_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.GOVUK_SIGNIN_JOURNEY_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.PERSISTENT_SESSION_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachOrchSessionIdToLogs;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachSessionIdToLogs;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachTraceId;
import static uk.gov.di.orchestration.shared.helpers.RequestHeaderHelper.getHeaderValueFromHeaders;
import static uk.gov.di.orchestration.shared.services.AuditService.MetadataPair.pair;

public class AuthCodeHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(AuthCodeHandler.class);

    private final OrchSessionService orchSessionService;
    private final AuthenticationUserInfoStorageService authUserInfoStorageService;
    private final AuthCodeResponseGenerationService authCodeResponseService;
    private final OrchAuthCodeService orchAuthCodeService;
    private final OrchestrationAuthorizationService orchestrationAuthorizationService;
    private final OrchClientSessionService orchClientSessionService;
    private final AuditService auditService;
    private final CloudwatchMetricsService cloudwatchMetricsService;
    private final ConfigurationService configurationService;
    private final DynamoClientService dynamoClientService;

    public AuthCodeHandler(
            OrchSessionService orchSessionService,
            AuthenticationUserInfoStorageService authUserInfoStorageService,
            AuthCodeResponseGenerationService authCodeResponseService,
            OrchAuthCodeService orchAuthCodeService,
            OrchestrationAuthorizationService orchestrationAuthorizationService,
            OrchClientSessionService orchClientSessionService,
            AuditService auditService,
            CloudwatchMetricsService cloudwatchMetricsService,
            ConfigurationService configurationService,
            DynamoClientService dynamoClientService) {
        this.orchSessionService = orchSessionService;
        this.authUserInfoStorageService = authUserInfoStorageService;
        this.authCodeResponseService = authCodeResponseService;
        this.orchAuthCodeService = orchAuthCodeService;
        this.orchestrationAuthorizationService = orchestrationAuthorizationService;
        this.orchClientSessionService = orchClientSessionService;
        this.auditService = auditService;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
        this.configurationService = configurationService;
        this.dynamoClientService = dynamoClientService;
    }

    public AuthCodeHandler(ConfigurationService configurationService) {
        orchSessionService = new OrchSessionService(configurationService);
        authUserInfoStorageService = new AuthenticationUserInfoStorageService(configurationService);
        orchAuthCodeService = new OrchAuthCodeService(configurationService);
        orchestrationAuthorizationService =
                new OrchestrationAuthorizationService(configurationService);
        this.orchClientSessionService = new OrchClientSessionService(configurationService);
        auditService = new AuditService(configurationService);
        cloudwatchMetricsService = new CloudwatchMetricsService();
        this.configurationService = configurationService;
        authCodeResponseService = new AuthCodeResponseGenerationService(configurationService);
        dynamoClientService = new DynamoClientService(configurationService);
    }

    public AuthCodeHandler() {
        this(ConfigurationService.getInstance());
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        ThreadContext.clearMap();
        attachTraceId();
        attachLogFieldToLogs(AWS_REQUEST_ID, context.getAwsRequestId());
        return authCodeRequestHandler(input, context);
    }

    public APIGatewayProxyResponseEvent authCodeRequestHandler(
            APIGatewayProxyRequestEvent input, Context context) {
        String sessionId;
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
            orchSession = orchSessionService.getSession(sessionId).orElse(null);
            clientSessionId =
                    getHeaderValueFromHeaders(
                            input.getHeaders(),
                            CLIENT_SESSION_ID_HEADER,
                            configurationService.getHeadersCaseInsensitive());
            validateSessions(orchSession, clientSessionId);
        } catch (ProcessAuthRequestException e) {
            return generateApiGatewayProxyErrorResponse(e.getStatusCode(), e.getErrorResponse());
        }

        attachSessionIdToLogs(sessionId);
        attachOrchSessionIdToLogs(orchSession.getSessionId());
        attachLogFieldToLogs(CLIENT_SESSION_ID, clientSessionId);
        attachLogFieldToLogs(GOVUK_SIGNIN_JOURNEY_ID, clientSessionId);

        LOG.info("Processing request");

        Optional<String> emailOptional;
        Optional<String> subjectIdOptional;
        Optional<String> internalCommonSubjectIdOptional;
        boolean isDocAppJourney;
        AuthenticationRequest authenticationRequest = null;
        OrchClientSessionItem orchClientSession;
        ClientID clientID;
        ClientRegistry client;
        AuthorizationCode authCode;
        AuthenticationSuccessResponse authenticationResponse;
        URI redirectUri;
        State state;
        try {
            orchClientSession = getClientSession(input);
            authenticationRequest =
                    AuthenticationRequest.parse(orchClientSession.getAuthRequestParams());

            clientID = authenticationRequest.getClientID();
            attachLogFieldToLogs(CLIENT_ID, clientID.getValue());
            attachLogFieldToLogs(
                    PERSISTENT_SESSION_ID,
                    PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders()));

            redirectUri = authenticationRequest.getRedirectionURI();
            state = authenticationRequest.getState();

            isDocAppJourney = isDocCheckingAppUserWithSubjectId(orchClientSession);

            if (!isDocAppJourney) {
                var authUserInfo =
                        getAuthUserInfo(
                                        authUserInfoStorageService,
                                        orchSession.getInternalCommonSubjectId(),
                                        clientSessionId)
                                .orElseThrow(() -> new AuthCodeException("authUserInfo not found"));
                emailOptional = Optional.of(authUserInfo.getEmailAddress());
                subjectIdOptional =
                        Optional.of(
                                authUserInfo.getStringClaim(
                                        AuthUserInfoClaims.LOCAL_ACCOUNT_ID.getValue()));
                internalCommonSubjectIdOptional =
                        Optional.of(orchSession.getInternalCommonSubjectId());
            } else {
                emailOptional = Optional.empty();
                subjectIdOptional = Optional.empty();
                internalCommonSubjectIdOptional = Optional.empty();
            }

            client =
                    dynamoClientService
                            .getClient(clientID.getValue())
                            .orElseThrow(() -> new ClientNotFoundException(clientID.getValue()));

            if (!orchestrationAuthorizationService.isClientRedirectUriValid(client, redirectUri)) {
                return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1016);
            }
        } catch (ProcessAuthRequestException e) {
            return generateApiGatewayProxyErrorResponse(e.getStatusCode(), e.getErrorResponse());
        } catch (ClientNotFoundException e) {
            return processClientNotFoundException(authenticationRequest);
        } catch (AuthCodeException e) {
            return processUserNotFoundException(authenticationRequest);
        } catch (ParseException e) {
            return processParseException(e);
        }

        try {
            authCode =
                    generateAuthCode(
                            clientID,
                            emailOptional,
                            clientSessionId,
                            orchSession.getAuthTime(),
                            internalCommonSubjectIdOptional);
        } catch (OrchAuthCodeException e) {
            LOG.error(
                    "Failed to generate and save authorisation code to orch auth code DynamoDB store. Error: {}",
                    e.getMessage());
            return generateApiGatewayProxyResponse(500, "Internal server error");
        }
        authenticationResponse =
                orchestrationAuthorizationService.generateSuccessfulAuthResponse(
                        authenticationRequest, authCode, redirectUri, state);

        LOG.info("Successfully processed request");

        try {
            var persistentSessionId =
                    PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders());
            var ipAddress = IpAddressHelper.extractIpAddress(input);
            String rpPairwiseId = AuditService.UNKNOWN;
            String internalCommonSubjectId;
            if (isDocAppJourney) {
                LOG.info("Session not saved for DocCheckingAppUser");
                internalCommonSubjectId = orchClientSession.getDocAppSubjectId();
            } else {
                internalCommonSubjectId = orchSession.getInternalCommonSubjectId();
                rpPairwiseId =
                        orchClientSession.getCorrectPairwiseIdGivenSubjectType(
                                client.getSubjectType());
            }
            sendAuditEvent(
                    authenticationRequest,
                    orchSession,
                    orchClientSession,
                    ipAddress,
                    persistentSessionId,
                    emailOptional,
                    subjectIdOptional,
                    rpPairwiseId,
                    internalCommonSubjectId,
                    authCode);

            sendCloudwatchMetrics(
                    orchSession, orchClientSession, clientID, isDocAppJourney, client);
            authCodeResponseService.saveSession(isDocAppJourney, orchSessionService, orchSession);
            LOG.info("Generating successful auth code response");
            return generateApiGatewayProxyResponse(
                    200,
                    new uk.gov.di.orchestration.entity.AuthCodeResponse(
                            authenticationResponse.toURI().toString()));
        } catch (JsonException e) {
            throw new RuntimeException(e);
        }
    }

    private void sendAuditEvent(
            AuthenticationRequest authenticationRequest,
            OrchSessionItem orchSession,
            OrchClientSessionItem orchClientSession,
            String ipAddress,
            String persistentSessionId,
            Optional<String> emailOptional,
            Optional<String> subjectIdOptional,
            String rpPairwiseId,
            String internalPairwiseSubjectId,
            AuthorizationCode authCode) {
        var metadataPairs = new ArrayList<AuditService.MetadataPair>();
        metadataPairs.add(
                pair("internalSubjectId", subjectIdOptional.orElse(AuditService.UNKNOWN)));
        metadataPairs.add(pair("isNewAccount", orchSession.getIsNewAccount()));
        metadataPairs.add(pair("rpPairwiseId", rpPairwiseId));
        metadataPairs.add(pair("authCode", authCode));
        if (authenticationRequest.getNonce() != null) {
            metadataPairs.add(pair("nonce", authenticationRequest.getNonce().getValue()));
        }

        auditService.submitAuditEvent(
                OidcAuditableEvent.AUTH_CODE_ISSUED,
                authenticationRequest.getClientID().getValue(),
                TxmaAuditUser.user()
                        .withGovukSigninJourneyId(orchClientSession.getClientSessionId())
                        .withSessionId(orchSession.getSessionId())
                        .withUserId(internalPairwiseSubjectId)
                        .withEmail(emailOptional.orElse(AuditService.UNKNOWN))
                        .withIpAddress(ipAddress)
                        .withPersistentSessionId(persistentSessionId),
                metadataPairs.toArray(AuditService.MetadataPair[]::new));
    }

    private void sendCloudwatchMetrics(
            OrchSessionItem orchSession,
            OrchClientSessionItem orchClientSession,
            ClientID clientID,
            boolean isDocAppJourney,
            ClientRegistry client) {
        var dimensions =
                authCodeResponseService.getDimensions(
                        orchSession,
                        orchClientSession.getClientName(),
                        clientID.getValue(),
                        isDocAppJourney);
        if (!isDocAppJourney) {
            authCodeResponseService.processVectorOfTrust(orchClientSession, dimensions);
        }

        cloudwatchMetricsService.incrementCounter("SignIn", dimensions);

        cloudwatchMetricsService.incrementSignInByClient(
                orchSession.getIsNewAccount(),
                clientID.getValue(),
                orchClientSession.getClientName());
        cloudwatchMetricsService.incrementCounter(
                "orchIdentityJourneyCompleted",
                Map.of(
                        "clientName", client.getClientName(),
                        "clientId", clientID.getValue()));
    }

    private static Optional<UserInfo> getAuthUserInfo(
            AuthenticationUserInfoStorageService authUserInfoStorageService,
            String internalCommonSubjectId,
            String clientSessionId) {

        if (internalCommonSubjectId == null || internalCommonSubjectId.isBlank()) {
            return Optional.empty();
        }

        try {
            return authUserInfoStorageService.getAuthenticationUserInfo(
                    internalCommonSubjectId, clientSessionId);
        } catch (ParseException e) {
            LOG.warn("error parsing authUserInfo. Message: {}", e.getMessage());
            return Optional.empty();
        }
    }

    private void validateSessions(OrchSessionItem orchSession, String clientSessionId)
            throws ProcessAuthRequestException {
        if (Objects.isNull(orchSession)) {
            throw new ProcessAuthRequestException(400, ErrorResponse.ERROR_1000);
        }
        if (Objects.isNull(clientSessionId)) {
            throw new ProcessAuthRequestException(400, ErrorResponse.ERROR_1018);
        }
    }

    private OrchClientSessionItem getClientSession(APIGatewayProxyRequestEvent input)
            throws ProcessAuthRequestException {
        var orchClientSession =
                orchClientSessionService
                        .getClientSessionFromRequestHeaders(input.getHeaders())
                        .orElse(null);
        if (Objects.isNull(orchClientSession)) {
            LOG.info("ClientSession not found");
            throw new ProcessAuthRequestException(400, ErrorResponse.ERROR_1018);
        }
        return orchClientSession;
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

    private APIGatewayProxyResponseEvent processUserNotFoundException(
            AuthenticationRequest authenticationRequest) {
        var errorResponse =
                orchestrationAuthorizationService.generateAuthenticationErrorResponse(
                        authenticationRequest,
                        OAuth2Error.ACCESS_DENIED,
                        authenticationRequest.getRedirectionURI(),
                        authenticationRequest.getState());
        return generateResponse(400, new AuthCodeResponse(errorResponse.toURI().toString()));
    }

    private AuthorizationCode generateAuthCode(
            ClientID clientID,
            Optional<String> emailOptional,
            String clientSessionId,
            Long authTime,
            Optional<String> internalCommonSubjectId) {

        return orchAuthCodeService.generateAndSaveAuthorisationCode(
                clientID.getValue(),
                clientSessionId,
                emailOptional.orElse(null),
                authTime,
                internalCommonSubjectId.orElse(null));
    }
}

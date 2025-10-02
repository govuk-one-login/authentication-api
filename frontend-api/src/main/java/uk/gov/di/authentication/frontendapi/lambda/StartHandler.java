package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.id.State;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.ReauthFailureReasons;
import uk.gov.di.authentication.frontendapi.entity.StartRequest;
import uk.gov.di.authentication.frontendapi.entity.StartResponse;
import uk.gov.di.authentication.frontendapi.helpers.ReauthMetadataBuilder;
import uk.gov.di.authentication.frontendapi.services.StartService;
import uk.gov.di.authentication.shared.domain.CloudwatchMetrics;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.ReauthAuthenticationAttemptsHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.serialization.Json.JsonException;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationAttemptsService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.shared.state.UserContext;
import uk.gov.di.authentication.userpermissions.PermissionDecisionManager;
import uk.gov.di.authentication.userpermissions.entity.UserPermissionContext;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static uk.gov.di.authentication.frontendapi.helpers.ReauthMetadataBuilder.getReauthFailureReasonFromCountTypes;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.ENVIRONMENT;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.FAILURE_REASON;
import static uk.gov.di.authentication.shared.domain.RequestHeaders.CLIENT_SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.domain.RequestHeaders.SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.entity.CredentialTrustLevel.retrieveCredentialTrustLevel;
import static uk.gov.di.authentication.shared.entity.LevelOfConfidence.retrieveLevelOfConfidence;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.CLIENT_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.CLIENT_SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.GOVUK_SIGNIN_JOURNEY_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.PERSISTENT_SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachSessionIdToLogs;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachTraceId;
import static uk.gov.di.authentication.shared.helpers.PersistentIdHelper.extractPersistentIdFromHeaders;
import static uk.gov.di.authentication.shared.helpers.RequestHeaderHelper.getHeaderValueFromHeaders;
import static uk.gov.di.authentication.shared.helpers.RequestHeaderHelper.getOptionalHeaderValueFromHeaders;
import static uk.gov.di.authentication.shared.helpers.TxmaAuditHelper.getTxmaAuditEncodedHeader;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;

public class StartHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(StartHandler.class);

    protected static final String REAUTHENTICATE_HEADER = "Reauthenticate";
    private final AuditService auditService;
    private final StartService startService;
    private final AuthSessionService authSessionService;
    private final ConfigurationService configurationService;
    private final AuthenticationAttemptsService authenticationAttemptsService;
    private final CloudwatchMetricsService cloudwatchMetricsService;
    private final PermissionDecisionManager permissionDecisionManager;
    private final Json objectMapper = SerializationService.getInstance();

    public StartHandler(
            AuditService auditService,
            StartService startService,
            AuthSessionService authSessionService,
            ConfigurationService configurationService,
            AuthenticationAttemptsService authenticationAttemptsService,
            CloudwatchMetricsService cloudwatchMetricsService,
            PermissionDecisionManager permissionDecisionManager) {
        this.auditService = auditService;
        this.startService = startService;
        this.authSessionService = authSessionService;
        this.configurationService = configurationService;
        this.authenticationAttemptsService = authenticationAttemptsService;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
        this.permissionDecisionManager = permissionDecisionManager;
    }

    public StartHandler(ConfigurationService configurationService) {
        this.auditService = new AuditService(configurationService);
        this.authenticationAttemptsService =
                new AuthenticationAttemptsService(configurationService);
        this.startService = new StartService(new DynamoService(configurationService));
        this.authSessionService = new AuthSessionService(configurationService);
        this.configurationService = configurationService;
        this.cloudwatchMetricsService = new CloudwatchMetricsService();
        this.permissionDecisionManager = new PermissionDecisionManager(configurationService);
    }

    public StartHandler() {
        this(ConfigurationService.getInstance());
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        ThreadContext.clearMap();
        attachTraceId();
        LOG.info("Start request received");
        var sessionIdOpt =
                getOptionalHeaderValueFromHeaders(
                        input.getHeaders(),
                        SESSION_ID_HEADER,
                        configurationService.getHeadersCaseInsensitive());
        if (sessionIdOpt.isEmpty()) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.SESSION_ID_MISSING);
        }

        var sessionId = sessionIdOpt.get();

        attachSessionIdToLogs(sessionId);
        attachLogFieldToLogs(
                PERSISTENT_SESSION_ID, extractPersistentIdFromHeaders(input.getHeaders()));

        var clientSessionIdOpt =
                getOptionalHeaderValueFromHeaders(
                        input.getHeaders(),
                        CLIENT_SESSION_ID_HEADER,
                        configurationService.getHeadersCaseInsensitive());
        if (clientSessionIdOpt.isEmpty()) {
            return generateApiGatewayProxyErrorResponse(
                    400, ErrorResponse.INVALID_CLIENT_SESSION_ID);
        }
        attachLogFieldToLogs(CLIENT_SESSION_ID, clientSessionIdOpt.get());
        attachLogFieldToLogs(GOVUK_SIGNIN_JOURNEY_ID, clientSessionIdOpt.get());

        StartRequest startRequest;
        try {
            startRequest = objectMapper.readValue(input.getBody(), StartRequest.class);
        } catch (JsonException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.REQUEST_MISSING_PARAMS);
        }

        boolean isUserAuthenticatedWithValidProfile;
        try {
            var authSession =
                    authSessionService.getUpdatedPreviousSessionOrCreateNew(
                            Optional.ofNullable(startRequest.previousSessionId())
                                    .filter(s -> !s.isBlank()),
                            sessionId);
            LOG.info("Start session retrieved");
            var requestedCredentialTrustLevel =
                    retrieveCredentialTrustLevel(startRequest.requestedCredentialStrength());
            authSession.setRequestedCredentialStrength(requestedCredentialTrustLevel);
            if (startRequest.requestedLevelOfConfidence() != null) {
                authSession.setRequestedLevelOfConfidence(
                        retrieveLevelOfConfidence(startRequest.requestedLevelOfConfidence()));
            }
            authSession.setClientId(startRequest.clientId());
            authSession.setClientName(startRequest.clientName());
            authSession.setIsSmokeTest(startRequest.isSmokeTest());
            authSession.setIsOneLoginService(startRequest.isOneLoginService());
            authSession.setSubjectType(startRequest.subjectType());
            authSession.setRpSectorIdentifierHost(startRequest.rpSectorIdentifierHost());

            isUserAuthenticatedWithValidProfile =
                    startRequest.authenticated() && !startService.isUserProfileEmpty(authSession);

            var upliftRequired =
                    startService.isUpliftRequired(
                            requestedCredentialTrustLevel,
                            authSession.getAchievedCredentialStrength());

            authSessionService.addSession(authSession.withUpliftRequired(upliftRequired));

            var userContext = startService.buildUserContext(authSession);

            var scopes = List.of(startRequest.scope().split(" "));
            var redirectURI = new URI(startRequest.redirectUri());
            var state = new State(startRequest.state());
            attachLogFieldToLogs(CLIENT_ID, authSession.getClientId());
            var clientStartInfo =
                    startService.buildClientStartInfo(
                            startRequest.serviceType(),
                            authSession.getClientName(),
                            scopes,
                            redirectURI,
                            state,
                            startRequest.isCookieConsentShared(),
                            startRequest.isOneLoginService());

            var cookieConsent =
                    startService.getCookieConsentValue(
                            startRequest.cookieConsent(), startRequest.isCookieConsentShared());
            var gaTrackingId = startRequest.ga();
            var reauthenticateHeader =
                    getHeaderValueFromHeaders(
                            input.getHeaders(),
                            REAUTHENTICATE_HEADER,
                            configurationService.getHeadersCaseInsensitive());
            var reauthenticate =
                    reauthenticateHeader != null && reauthenticateHeader.equals("true");
            LOG.info(
                    "reauthenticateHeader: {} reauthenticate: {}",
                    reauthenticateHeader,
                    reauthenticate);

            Optional<String> maybeInternalSubject =
                    Optional.ofNullable(authSession.getInternalCommonSubjectId());

            var clientSessionId =
                    getHeaderValueFromHeaders(
                            input.getHeaders(),
                            CLIENT_SESSION_ID_HEADER,
                            configurationService.getHeadersCaseInsensitive());
            var txmaAuditHeader = getTxmaAuditEncodedHeader(input);
            String phoneNumber = AuditService.UNKNOWN;

            var auditContext =
                    new AuditContext(
                            authSession.getClientId(),
                            clientSessionId,
                            sessionId,
                            maybeInternalSubject.orElse(AuditService.UNKNOWN),
                            userContext
                                    .getUserProfile()
                                    .map(UserProfile::getEmail)
                                    .orElse(AuditService.UNKNOWN),
                            IpAddressHelper.extractIpAddress(input),
                            phoneNumber,
                            extractPersistentIdFromHeaders(input.getHeaders()),
                            txmaAuditHeader,
                            new ArrayList<>());

            if (reauthenticate) {
                emitReauthRequestedObservability(startRequest, auditContext);
            }

            boolean isBlockedForReauth = false;
            if (configurationService.isAuthenticationAttemptsServiceEnabled() && reauthenticate) {
                isBlockedForReauth =
                        checkUserIsBlockedForReauthAndEmitFailureAuditEvent(
                                maybeInternalSubject, auditContext, startRequest);
            }

            var userStartInfo =
                    startService.buildUserStartInfo(
                            userContext,
                            cookieConsent,
                            gaTrackingId,
                            startRequest.isIdentityVerificationRequired(),
                            reauthenticate,
                            isBlockedForReauth,
                            isUserAuthenticatedWithValidProfile,
                            upliftRequired);

            StartResponse startResponse = new StartResponse(userStartInfo, clientStartInfo);

            auditService.submitAuditEvent(
                    FrontendAuditableEvent.AUTH_START_INFO_FOUND,
                    auditContext,
                    pair("internalSubjectId", maybeInternalSubject.orElse(AuditService.UNKNOWN)));

            return generateApiGatewayProxyResponse(200, startResponse);

        } catch (JsonException e) {
            var errorMessage = "Unable to serialize start response";
            LOG.error(errorMessage, e);
            return generateApiGatewayProxyResponse(400, errorMessage);
        } catch (URISyntaxException e) {
            var errorMessage = "Unable to parse redirect URI";
            LOG.error(errorMessage, e);
            return generateApiGatewayProxyResponse(400, errorMessage);
        }
    }

    private boolean checkUserIsBlockedForReauthAndEmitFailureAuditEvent(
            Optional<String> maybeInternalSubjectId,
            AuditContext auditContext,
            StartRequest startRequest) {
        var reauthCountTypesToCounts =
                maybeInternalSubjectId
                        .map(
                                subjectId ->
                                        authenticationAttemptsService
                                                .getCountsByJourneyForSubjectIdAndRpPairwiseId(
                                                        subjectId,
                                                        startRequest.rpPairwiseIdForReauth(),
                                                        JourneyType.REAUTHENTICATION))
                        .orElse(
                                authenticationAttemptsService.getCountsByJourney(
                                        startRequest.rpPairwiseIdForReauth(),
                                        JourneyType.REAUTHENTICATION));
        var blockedCountTypes =
                ReauthAuthenticationAttemptsHelper.countTypesWhereUserIsBlockedForReauth(
                        reauthCountTypesToCounts, configurationService);
        if (!blockedCountTypes.isEmpty() && maybeInternalSubjectId.isPresent()) {
            ReauthFailureReasons failureReason =
                    getReauthFailureReasonFromCountTypes(blockedCountTypes);
            auditService.submitAuditEvent(
                    FrontendAuditableEvent.AUTH_REAUTH_FAILED,
                    auditContext,
                    ReauthMetadataBuilder.builder(startRequest.rpPairwiseIdForReauth())
                            .withAllIncorrectAttemptCounts(reauthCountTypesToCounts)
                            .withFailureReason(failureReason)
                            .build());
            cloudwatchMetricsService.incrementCounter(
                    CloudwatchMetrics.REAUTH_FAILED.getValue(),
                    Map.of(
                            ENVIRONMENT.getValue(),
                            configurationService.getEnvironment(),
                            FAILURE_REASON.getValue(),
                            failureReason == null ? "unknown" : failureReason.getValue()));
        }
        return !blockedCountTypes.isEmpty();
    }

    private void emitReauthRequestedObservability(
            StartRequest startRequest, AuditContext auditContext) {
        var metadataPairs = new ArrayList<AuditService.MetadataPair>();
        var previousSigninJourneyId = startRequest.previousGovUkSigninJourneyId();
        if (!(previousSigninJourneyId == null || previousSigninJourneyId.isEmpty())) {
            metadataPairs.add(pair("previous_govuk_signin_journey_id", previousSigninJourneyId));
        }
        var rpPairwiseId = startRequest.rpPairwiseIdForReauth();
        if (!(rpPairwiseId == null || rpPairwiseId.isEmpty())) {
            metadataPairs.add(pair("rpPairwiseId", rpPairwiseId));
        }
        auditService.submitAuditEvent(
                FrontendAuditableEvent.AUTH_REAUTH_REQUESTED,
                auditContext,
                metadataPairs.toArray(AuditService.MetadataPair[]::new));
        cloudwatchMetricsService.incrementCounter(
                CloudwatchMetrics.REAUTH_REQUESTED.getValue(),
                Map.of(ENVIRONMENT.getValue(), configurationService.getEnvironment()));
    }

    private UserPermissionContext buildUserPermissionContext(
            AuthSessionItem authSession, StartRequest startRequest, UserContext userContext) {
        return new UserPermissionContext(
                authSession.getInternalCommonSubjectId(),
                startRequest.rpPairwiseIdForReauth(),
                userContext.getUserProfile().map(UserProfile::getEmail).orElse(null),
                authSession);
    }
}

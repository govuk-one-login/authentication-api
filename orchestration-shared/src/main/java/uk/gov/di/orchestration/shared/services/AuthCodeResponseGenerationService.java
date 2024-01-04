package uk.gov.di.orchestration.shared.services;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.entity.AuthCodeResponse;
import uk.gov.di.orchestration.shared.domain.AuditableEvent;
import uk.gov.di.orchestration.shared.entity.ClientSession;
import uk.gov.di.orchestration.shared.entity.CredentialTrustLevel;
import uk.gov.di.orchestration.shared.entity.LevelOfConfidence;
import uk.gov.di.orchestration.shared.entity.Session;
import uk.gov.di.orchestration.shared.exceptions.ClientNotFoundException;
import uk.gov.di.orchestration.shared.exceptions.UserNotFoundException;
import uk.gov.di.orchestration.shared.helpers.ClientSubjectHelper;
import uk.gov.di.orchestration.shared.helpers.IpAddressHelper;
import uk.gov.di.orchestration.shared.helpers.PersistentIdHelper;
import uk.gov.di.orchestration.shared.serialization.Json;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import static uk.gov.di.orchestration.shared.entity.Session.AccountState.EXISTING;
import static uk.gov.di.orchestration.shared.entity.Session.AccountState.EXISTING_DOC_APP_JOURNEY;
import static uk.gov.di.orchestration.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.orchestration.shared.services.AuditService.MetadataPair.pair;

public class AuthCodeResponseGenerationService {
    private static final Logger LOG = LogManager.getLogger(AuthCodeResponseGenerationService.class);

    private final AuditService auditService;
    private final CloudwatchMetricsService cloudwatchMetricsService;
    private final ConfigurationService configurationService;
    private final DynamoService dynamoService;
    private final DynamoClientService dynamoClientService;

    public AuthCodeResponseGenerationService(
            AuditService auditService,
            CloudwatchMetricsService cloudwatchMetricsService,
            ConfigurationService configurationService,
            DynamoService dynamoService,
            DynamoClientService dynamoClientService) {
        this.auditService = auditService;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
        this.configurationService = configurationService;
        this.dynamoService = dynamoService;
        this.dynamoClientService = dynamoClientService;
    }

    public AuthCodeResponseGenerationService(ConfigurationService configurationService) {
        auditService = new AuditService(configurationService);
        cloudwatchMetricsService = new CloudwatchMetricsService(configurationService);
        this.configurationService = configurationService;
        dynamoService = new DynamoService(configurationService);
        dynamoClientService = new DynamoClientService(configurationService);
    }

    public AuthCodeResponseGenerationService() {
        this(ConfigurationService.getInstance());
    }

    public APIGatewayProxyResponseEvent generateAuthCodeResponse(
            APIGatewayProxyRequestEvent input,
            boolean isTestJourney,
            boolean docAppJourney,
            AuthenticationRequest authenticationRequest,
            AuthorizationCode authCode,
            Session session,
            String clientSessionId,
            ClientSession clientSession,
            SessionService sessionService,
            ClientID clientID,
            AuthenticationSuccessResponse authenticationResponse,
            AuditableEvent auditableEvent)
            throws UserNotFoundException, ClientNotFoundException, Json.JsonException {

        var dimensions =
                getDimensions(session, clientSession, clientID, isTestJourney, docAppJourney);

        var subjectId = AuditService.UNKNOWN;
        var rpPairwiseId = AuditService.UNKNOWN;
        String internalCommonPairwiseSubjectId;
        if (docAppJourney) {
            LOG.info("Session not saved for DocCheckingAppUser");
            internalCommonPairwiseSubjectId = clientSession.getDocAppSubjectId().getValue();
        } else {
            processVectorOfTrust(clientSession, dimensions);
            internalCommonPairwiseSubjectId = session.getInternalCommonSubjectIdentifier();
            subjectId = getSubjectId(session);
            rpPairwiseId = getRpPairwiseId(session, clientID);
        }

        auditService.submitAuditEvent(
                auditableEvent,
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
        if (docAppJourney) {
            sessionService.save(session.setNewAccount(EXISTING_DOC_APP_JOURNEY));
        } else {
            sessionService.save(session.setAuthenticated(true).setNewAccount(EXISTING));
        }

        LOG.info("Generating successful auth code response");
        return generateApiGatewayProxyResponse(
                200, new AuthCodeResponse(authenticationResponse.toURI().toString()));
    }

    private Map<String, String> getDimensions(
            Session session,
            ClientSession clientSession,
            ClientID clientID,
            boolean isTestJourney,
            boolean docAppJourney) {
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
        return dimensions;
    }

    private void processVectorOfTrust(ClientSession clientSession, Map<String, String> dimensions) {
        var mfaNotRequired =
                clientSession
                        .getEffectiveVectorOfTrust()
                        .getCredentialTrustLevel()
                        .equals(CredentialTrustLevel.LOW_LEVEL);
        var levelOfConfidence = LevelOfConfidence.NONE.getValue();
        if (clientSession.getEffectiveVectorOfTrust().containsLevelOfConfidence()) {
            levelOfConfidence =
                    clientSession.getEffectiveVectorOfTrust().getLevelOfConfidence().getValue();
        }
        dimensions.put("MfaRequired", mfaNotRequired ? "No" : "Yes");
        dimensions.put("RequestedLevelOfConfidence", levelOfConfidence);
    }

    private String getSubjectId(Session session) throws UserNotFoundException {
        var userProfile =
                dynamoService
                        .getUserProfileByEmailMaybe(session.getEmailAddress())
                        .orElseThrow(
                                () ->
                                        new UserNotFoundException(
                                                "Unable to find user with given email address"));
        return Objects.isNull(session.getEmailAddress())
                ? AuditService.UNKNOWN
                : userProfile.getSubjectID();
    }

    private String getRpPairwiseId(Session session, ClientID clientID)
            throws UserNotFoundException, ClientNotFoundException {
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
                        .orElseThrow(() -> new ClientNotFoundException(clientID.getValue()));
        return ClientSubjectHelper.getSubject(
                        userProfile,
                        client,
                        dynamoService,
                        configurationService.getInternalSectorUri())
                .getValue();
    }
}

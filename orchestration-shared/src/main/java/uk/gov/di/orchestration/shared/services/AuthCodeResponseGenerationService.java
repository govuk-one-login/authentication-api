package uk.gov.di.orchestration.shared.services;

import com.nimbusds.oauth2.sdk.id.ClientID;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.shared.entity.ClientSession;
import uk.gov.di.orchestration.shared.entity.CredentialTrustLevel;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem;
import uk.gov.di.orchestration.shared.entity.Session;
import uk.gov.di.orchestration.shared.entity.VectorOfTrust;
import uk.gov.di.orchestration.shared.exceptions.ClientNotFoundException;
import uk.gov.di.orchestration.shared.exceptions.UserNotFoundException;
import uk.gov.di.orchestration.shared.helpers.ClientSubjectHelper;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import static java.util.Objects.isNull;
import static uk.gov.di.orchestration.shared.entity.Session.AccountState.EXISTING;
import static uk.gov.di.orchestration.shared.entity.Session.AccountState.EXISTING_DOC_APP_JOURNEY;

public class AuthCodeResponseGenerationService {
    private static final Logger LOG = LogManager.getLogger(AuthCodeResponseGenerationService.class);

    private final ConfigurationService configurationService;
    private final DynamoService dynamoService;

    public AuthCodeResponseGenerationService(
            ConfigurationService configurationService, DynamoService dynamoService) {
        this.configurationService = configurationService;
        this.dynamoService = dynamoService;
    }

    public AuthCodeResponseGenerationService(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        dynamoService = new DynamoService(configurationService);
    }

    public AuthCodeResponseGenerationService() {
        this(ConfigurationService.getInstance());
    }

    public Map<String, String> getDimensions(
            OrchSessionItem orchSession,
            ClientSession clientSession,
            String clientSessionId,
            boolean isTestJourney,
            boolean docAppJourney) {
        Map<String, String> dimensions =
                new HashMap<>(
                        Map.of(
                                "Account",
                                orchSession.getIsNewAccount().name(),
                                "Environment",
                                configurationService.getEnvironment(),
                                "Client",
                                clientSessionId,
                                "IsTest",
                                Boolean.toString(isTestJourney),
                                "IsDocApp",
                                Boolean.toString(docAppJourney),
                                "ClientName",
                                clientSession.getClientName()));

        if (Objects.nonNull(orchSession.getVerifiedMfaMethodType())) {
            dimensions.put("MfaMethod", orchSession.getVerifiedMfaMethodType());
        } else {
            LOG.info(
                    "No mfa method to set. User is either authenticated or signing in from a low level service");
        }
        return dimensions;
    }

    public void processVectorOfTrust(ClientSession clientSession, Map<String, String> dimensions) {
        CredentialTrustLevel lowestRequestedCredentialTrustLevel =
                VectorOfTrust.getLowestCredentialTrustLevel(clientSession.getVtrList());
        var mfaNotRequired =
                lowestRequestedCredentialTrustLevel.equals(CredentialTrustLevel.LOW_LEVEL);
        dimensions.put("MfaRequired", mfaNotRequired ? "No" : "Yes");
        dimensions.put(
                "RequestedLevelOfConfidence", clientSession.getVtrLocsAsCommaSeparatedString());
    }

    public String getSubjectId(Session session) throws UserNotFoundException {
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

    public String getRpPairwiseId(
            Session session, ClientID clientID, DynamoClientService dynamoClientService)
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
                        configurationService.getInternalSectorURI())
                .getValue();
    }

    public void saveSession(
            boolean docAppJourney,
            SessionService sessionService,
            Session session,
            OrchSessionService orchSessionService,
            OrchSessionItem orchSession,
            ClientSession clientSession) {

        setCurrentCredentialStrength(orchSession, clientSession);

        if (docAppJourney) {
            sessionService.storeOrUpdateSession(session.setNewAccount(EXISTING_DOC_APP_JOURNEY));
            orchSessionService.updateSession(
                    orchSession.withAccountState(
                            OrchSessionItem.AccountState.EXISTING_DOC_APP_JOURNEY));
        } else {
            sessionService.storeOrUpdateSession(
                    session.setAuthenticated(true).setNewAccount(EXISTING));
            orchSessionService.updateSession(
                    orchSession
                            .withAuthenticated(true)
                            .withAccountState(OrchSessionItem.AccountState.EXISTING));
        }
        // ATO-975 logging to make sure there are no differences in production
        LOG.info(
                "Shared session current credential strength: {}",
                session.getCurrentCredentialStrength());
        LOG.info(
                "Orch session current credential strength: {}",
                orchSession.getCurrentCredentialStrength());
        LOG.info(
                "Is shared session CCS equal to Orch session CCS: {}",
                Objects.equals(
                        session.getCurrentCredentialStrength(),
                        orchSession.getCurrentCredentialStrength()));
    }

    private void setCurrentCredentialStrength(
            OrchSessionItem orchSession, ClientSession clientSession) {
        CredentialTrustLevel lowestRequestedCredentialTrustLevel =
                VectorOfTrust.getLowestCredentialTrustLevel(clientSession.getVtrList());
        CredentialTrustLevel currentCredentialStrength = orchSession.getCurrentCredentialStrength();

        if (configurationService.isCurrentCredentialStrengthInOrchSessionEnabled()
                && (isNull(currentCredentialStrength)
                        || lowestRequestedCredentialTrustLevel.compareTo(currentCredentialStrength)
                                > 0)) {
            orchSession.setCurrentCredentialStrength(lowestRequestedCredentialTrustLevel);
        }
    }
}

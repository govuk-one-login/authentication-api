package uk.gov.di.orchestration.shared.services;

import com.nimbusds.oauth2.sdk.id.ClientID;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.shared.entity.ClientSession;
import uk.gov.di.orchestration.shared.entity.CredentialTrustLevel;
import uk.gov.di.orchestration.shared.entity.Session;
import uk.gov.di.orchestration.shared.entity.VectorOfTrust;
import uk.gov.di.orchestration.shared.exceptions.ClientNotFoundException;
import uk.gov.di.orchestration.shared.exceptions.UserNotFoundException;
import uk.gov.di.orchestration.shared.helpers.ClientSubjectHelper;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

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
            Session session,
            ClientSession clientSession,
            String clientSessionId,
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
                                clientSessionId,
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

    public void saveSession(boolean docAppJourney, SessionService sessionService, Session session) {
        if (docAppJourney) {
            sessionService.save(session.setNewAccount(EXISTING_DOC_APP_JOURNEY));
        } else {
            sessionService.save(session.setAuthenticated(true).setNewAccount(EXISTING));
        }
    }
}

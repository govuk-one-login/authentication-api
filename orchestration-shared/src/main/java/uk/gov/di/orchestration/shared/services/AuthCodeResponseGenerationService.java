package uk.gov.di.orchestration.shared.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.shared.entity.CredentialTrustLevel;
import uk.gov.di.orchestration.shared.entity.OrchClientSessionItem;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem;
import uk.gov.di.orchestration.shared.entity.Session;
import uk.gov.di.orchestration.shared.entity.VectorOfTrust;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import static uk.gov.di.orchestration.shared.entity.Session.AccountState.EXISTING;
import static uk.gov.di.orchestration.shared.entity.Session.AccountState.EXISTING_DOC_APP_JOURNEY;

public class AuthCodeResponseGenerationService {
    private static final Logger LOG = LogManager.getLogger(AuthCodeResponseGenerationService.class);

    private final ConfigurationService configurationService;

    public AuthCodeResponseGenerationService(ConfigurationService configurationService) {
        this.configurationService = configurationService;
    }

    public AuthCodeResponseGenerationService() {
        this(ConfigurationService.getInstance());
    }

    public Map<String, String> getDimensions(
            OrchSessionItem orchSession,
            String clientName,
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
                                clientName));

        if (Objects.nonNull(orchSession.getVerifiedMfaMethodType())) {
            dimensions.put("MfaMethod", orchSession.getVerifiedMfaMethodType());
        } else {
            LOG.info(
                    "No mfa method to set. User is either authenticated or signing in from a low level service");
        }
        return dimensions;
    }

    public void processVectorOfTrust(
            OrchClientSessionItem orchClientSession, Map<String, String> dimensions) {
        CredentialTrustLevel lowestRequestedCredentialTrustLevel =
                VectorOfTrust.getLowestCredentialTrustLevel(orchClientSession.getVtrList());
        var mfaNotRequired =
                lowestRequestedCredentialTrustLevel.equals(CredentialTrustLevel.LOW_LEVEL);
        dimensions.put("MfaRequired", mfaNotRequired ? "No" : "Yes");
        dimensions.put(
                "RequestedLevelOfConfidence", orchClientSession.getVtrLocsAsCommaSeparatedString());
    }

    public void saveSession(
            boolean docAppJourney,
            SessionService sessionService,
            Session session,
            String sessionId,
            OrchSessionService orchSessionService,
            OrchSessionItem orchSession) {

        if (docAppJourney) {
            sessionService.storeOrUpdateSession(
                    session.setNewAccount(EXISTING_DOC_APP_JOURNEY), sessionId);
            orchSessionService.updateSession(
                    orchSession.withAccountState(
                            OrchSessionItem.AccountState.EXISTING_DOC_APP_JOURNEY));
        } else {
            sessionService.storeOrUpdateSession(
                    session.setAuthenticated(true).setNewAccount(EXISTING), sessionId);
            orchSessionService.updateSession(
                    orchSession
                            .withAuthenticated(true)
                            .withAccountState(OrchSessionItem.AccountState.EXISTING));
        }
    }
}

package uk.gov.di.authentication.shared.services;

import uk.gov.di.authentication.shared.entity.ClientRegistry;

import java.util.List;
import java.util.Optional;

public interface ClientService {

    boolean isValidClient(String clientId);

    void addClient(
            String clientID,
            String clientName,
            List<String> redirectUris,
            List<String> contacts,
            List<String> scopes,
            String publicKey,
            List<String> postLogoutRedirectUris,
            String backChannelLogoutUri,
            String serviceType,
            String sectorIdentifierUri,
            String subjectType,
            List<String> claims,
            String clientType,
            boolean identityVerificationSupported,
            String clientSecret,
            String tokenAuthMethod);

    Optional<ClientRegistry> getClient(String clientId);

    boolean isTestJourney(String clientID, String emailAddress);
}

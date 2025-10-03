package uk.gov.di.orchestration.shared.services;

import com.nimbusds.oauth2.sdk.id.ClientID;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.UpdateClientConfigRequest;

import java.util.List;
import java.util.Optional;

public interface ClientService {

    boolean isValidClient(String clientId);

    void addClient(
            String clientID,
            String clientName,
            List<String> redirectUris,
            List<String> contacts,
            String publicKeySource,
            String publicKey,
            String jwksUrl,
            List<String> scopes,
            List<String> postLogoutRedirectUris,
            String backChannelLogoutUri,
            String serviceType,
            String sectorIdentifierUri,
            String subjectType,
            boolean jarValidationRequired,
            List<String> claims,
            String clientType,
            boolean identityVerificationSupported,
            String clientSecret,
            String tokenAuthMethod,
            String idTokenSigningAlgorithm,
            List<String> clientLoCs,
            String channel,
            boolean maxAgeEnabled,
            boolean pkceEnforced,
            String landingPageUrl);

    Optional<ClientRegistry> getClient(String clientId);

    ClientID generateClientID();

    ClientRegistry updateSSEClient(String clientId, UpdateClientConfigRequest updateRequest);

    boolean isTestJourney(String clientID, String emailAddress);
}

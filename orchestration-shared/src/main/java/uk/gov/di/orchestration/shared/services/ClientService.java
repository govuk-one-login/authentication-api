package uk.gov.di.orchestration.shared.services;

import com.nimbusds.oauth2.sdk.id.ClientID;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.UpdateClientConfigRequest;

import java.util.List;
import java.util.Optional;

public interface ClientService {

    boolean isValidClient(String clientId);

    // TODO: Remove once all uses have been deleted
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
            boolean consentRequired,
            boolean jarValidationRequired,
            List<String> claims,
            String clientType,
            boolean identityVerificationSupported,
            String clientSecret,
            String tokenAuthMethod,
            List<String> clientLoCs);

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
            boolean jarValidationRequired,
            List<String> claims,
            String clientType,
            boolean identityVerificationSupported,
            String clientSecret,
            String tokenAuthMethod,
            List<String> clientLoCs);

    Optional<ClientRegistry> getClient(String clientId);

    ClientID generateClientID();

    ClientRegistry updateClient(String clientId, UpdateClientConfigRequest updateRequest);

    boolean isTestJourney(String clientID, String emailAddress);
}

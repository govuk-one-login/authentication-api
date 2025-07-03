package uk.gov.di.authentication.oidc.entity;

import uk.gov.di.orchestration.shared.entity.ClientRegistry;

public record ClientRequestInfo(String clientID, Integer rateLimit) {

    public static ClientRequestInfo fromClientRegistry(ClientRegistry client) {
        return new ClientRequestInfo(client.getClientID(), client.getRateLimit());
    }
}

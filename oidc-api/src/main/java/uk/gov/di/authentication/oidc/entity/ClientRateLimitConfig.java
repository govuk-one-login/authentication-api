package uk.gov.di.authentication.oidc.entity;

import uk.gov.di.orchestration.shared.entity.ClientRegistry;

public record ClientRateLimitConfig(String clientID, Integer rateLimit) {

    public static ClientRateLimitConfig fromClientRegistry(ClientRegistry client) {
        return new ClientRateLimitConfig(client.getClientID(), client.getRateLimit());
    }
}

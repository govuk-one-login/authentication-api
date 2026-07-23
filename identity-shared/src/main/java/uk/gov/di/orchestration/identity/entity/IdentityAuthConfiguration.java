package uk.gov.di.orchestration.identity.entity;

import uk.gov.di.orchestration.shared.domain.AuditableEvent;
import uk.gov.di.orchestration.shared.entity.JwksCacheItem;

import java.net.URI;
import java.util.function.Supplier;

public record IdentityAuthConfiguration(
        String stateStoragePrefix,
        String clientId,
        String audience,
        URI authorisationUri,
        String callbackUri,
        String tokenSigningKeyAlias,
        Supplier<JwksCacheItem> jwksCacheItemSupplier,
        AuditableEvent auditEvent,
        String metricToIncrement) {}

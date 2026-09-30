package uk.gov.di.authentication.auditevents.entity.shared;

public record PasskeyInformation(
        String passkeyCredentialId, String passkeyAaguid, String passkeyCredentialDeviceType) {}

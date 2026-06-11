package uk.gov.di.authentication.auditevents.entity.shared.passkeys;

import java.util.List;

public record PasskeyAllowCredentials(
        String passkeyCredentialId, List<String> passkeyCredentialTransports) {}

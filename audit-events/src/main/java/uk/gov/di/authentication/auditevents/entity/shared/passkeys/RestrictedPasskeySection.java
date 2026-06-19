package uk.gov.di.authentication.auditevents.entity.shared.passkeys;

import java.util.List;

public record RestrictedPasskeySection(
        List<PasskeyAllowCredentials> passkeyAllowedCredentials, String passkeyCredentialId) {}

package uk.gov.di.authentication.shared.services.mfa;

import uk.gov.di.authentication.shared.entity.mfa.MFAMethodUpdateIdentifier;

public record MfaUpdateFailure(
        MfaUpdateFailureReason failureReason, MFAMethodUpdateIdentifier updateTypeIdentifier) {
    public MfaUpdateFailure(MfaUpdateFailureReason failureReason) {
        this(failureReason, null);
    }
}

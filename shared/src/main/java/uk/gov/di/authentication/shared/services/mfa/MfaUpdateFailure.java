package uk.gov.di.authentication.shared.services.mfa;

import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodUpdateIdentifier;

public record MfaUpdateFailure(
        MfaUpdateFailureReason failureReason,
        MFAMethodUpdateIdentifier updateTypeIdentifier,
        MFAMethod mfaMethodToUpdate) {
    public MfaUpdateFailure(MfaUpdateFailureReason failureReason) {
        this(failureReason, null, null);
    }
}

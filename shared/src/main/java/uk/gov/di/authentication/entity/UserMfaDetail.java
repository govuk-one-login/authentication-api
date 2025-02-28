package uk.gov.di.authentication.entity;

import uk.gov.di.authentication.shared.entity.MFAMethodType;

public record UserMfaDetail(
        boolean isMfaRequired,
        boolean mfaMethodVerified,
        MFAMethodType mfaMethodType,
        String phoneNumber) {
    public static UserMfaDetail noMfa() {
        return new UserMfaDetail(false, false, MFAMethodType.NONE, null);
    }
}

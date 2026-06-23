package uk.gov.di.authentication.entity;

import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;

public record UserMfaDetail(
        boolean mfaMethodVerified, MFAMethodType mfaMethodType, String phoneNumber) {
    public static UserMfaDetail noMfa() {
        return new UserMfaDetail(false, MFAMethodType.NONE, null);
    }
}

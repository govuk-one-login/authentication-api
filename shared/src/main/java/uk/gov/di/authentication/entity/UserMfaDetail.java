package uk.gov.di.authentication.entity;

import uk.gov.di.authentication.shared.entity.MFAMethodType;

public class UserMfaDetail {
    protected boolean isMfaRequired;
    protected boolean mfaMethodVerified;
    protected MFAMethodType mfaMethodType;

    public UserMfaDetail() {
        this.isMfaRequired = false;
        this.mfaMethodVerified = false;
        this.mfaMethodType = MFAMethodType.NONE;
    }

    public UserMfaDetail(
            boolean isMfaRequired, boolean mfaMethodVerified, MFAMethodType mfaMethodType) {
        this.isMfaRequired = isMfaRequired;
        this.mfaMethodVerified = mfaMethodVerified;
        this.mfaMethodType = mfaMethodType;
    }

    public boolean isMfaRequired() {
        return isMfaRequired;
    }

    public boolean isMfaMethodVerified() {
        return mfaMethodVerified;
    }

    public MFAMethodType getMfaMethodType() {
        return mfaMethodType;
    }
}

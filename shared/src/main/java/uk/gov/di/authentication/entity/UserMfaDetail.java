package uk.gov.di.authentication.entity;

import uk.gov.di.authentication.shared.entity.MFAMethodType;

public class UserMfaDetail {
    protected boolean isMfaRequired;
    protected boolean mfaMethodVerified;
    protected MFAMethodType mfaMethodType;
    protected String phoneNumber;

    public UserMfaDetail() {
        this.isMfaRequired = false;
        this.mfaMethodVerified = false;
        this.mfaMethodType = MFAMethodType.NONE;
    }

    public UserMfaDetail(
            boolean isMfaRequired,
            boolean mfaMethodVerified,
            MFAMethodType mfaMethodType,
            String phoneNumber) {
        this.isMfaRequired = isMfaRequired;
        this.mfaMethodVerified = mfaMethodVerified;
        this.mfaMethodType = mfaMethodType;
        this.phoneNumber = phoneNumber;
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

    public String getPhoneNumber() {
        return phoneNumber;
    }
}

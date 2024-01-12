package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.entity.MFAMethodType;

public class CheckUserExistsResponse {

    @SerializedName("email")
    @Expose
    private String email;

    @SerializedName("doesUserExist")
    @Expose
    private boolean doesUserExist;

    @SerializedName("mfaMethodType")
    @Expose
    private MFAMethodType mfaMethodType;

    @SerializedName("phoneNumberLastThree")
    @Expose
    private String phoneNumberLastThree;

    public CheckUserExistsResponse() {}

    public CheckUserExistsResponse(
            String email, boolean doesUserExist, MFAMethodType mfaMethodType) {
        this.email = email;
        this.doesUserExist = doesUserExist;
        this.mfaMethodType = mfaMethodType;
    }

    public CheckUserExistsResponse(
            String email,
            boolean doesUserExist,
            MFAMethodType mfaMethodType,
            String phoneNumberLastThree) {
        this.email = email;
        this.doesUserExist = doesUserExist;
        this.mfaMethodType = mfaMethodType;
        this.phoneNumberLastThree = phoneNumberLastThree;
    }

    public String getEmail() {
        return email;
    }

    public boolean doesUserExist() {
        return doesUserExist;
    }

    public MFAMethodType getMfaMethodType() {
        return mfaMethodType;
    }

    public String getPhoneNumberLastThree() {
        return phoneNumberLastThree;
    }
}

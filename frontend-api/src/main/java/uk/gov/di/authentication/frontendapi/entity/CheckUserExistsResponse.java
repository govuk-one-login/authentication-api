package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.entity.MFAMethodType;

import java.util.List;

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

    @SerializedName("lockoutInformation")
    @Expose
    private List<LockoutInformation> lockoutInformation;

    public CheckUserExistsResponse(
            String email,
            boolean doesUserExist,
            MFAMethodType mfaMethodType,
            String phoneNumberLastThree,
            List<LockoutInformation> lockoutInformation) {
        this.email = email;
        this.doesUserExist = doesUserExist;
        this.mfaMethodType = mfaMethodType;
        this.phoneNumberLastThree = phoneNumberLastThree;
        this.lockoutInformation = lockoutInformation;
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

    public List<LockoutInformation> getLockoutInformation() {
        return lockoutInformation;
    }
}

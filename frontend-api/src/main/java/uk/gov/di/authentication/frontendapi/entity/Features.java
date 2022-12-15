package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

public class Features {

    @SerializedName("updatePasswordHintTextVersion")
    @Expose
    private String updatePasswordHintTextVersion;

    public String getUpdatePasswordHintTextVersion() {
        return updatePasswordHintTextVersion;
    }

    public void setUpdatePasswordHintTextVersion(String updatePasswordHintTextVersion) {
        this.updatePasswordHintTextVersion = updatePasswordHintTextVersion;
    }

    @Override
    public String toString() {
        return "Features{"
                + "updatePasswordHintTextVersion='"
                + updatePasswordHintTextVersion
                + '\''
                + '}';
    }
}

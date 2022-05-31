package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

public class CheckUserExistsResponse {

    @SerializedName("email")
    @Expose
    private String email;

    @SerializedName("doesUserExist")
    @Expose
    private boolean doesUserExist;

    public CheckUserExistsResponse() {}

    public CheckUserExistsResponse(String email, boolean doesUserExist) {
        this.email = email;
        this.doesUserExist = doesUserExist;
    }

    public String getEmail() {
        return email;
    }

    public boolean doesUserExist() {
        return doesUserExist;
    }
}

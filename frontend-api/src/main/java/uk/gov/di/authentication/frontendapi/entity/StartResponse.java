package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import jakarta.validation.constraints.NotNull;

public class StartResponse {

    @SerializedName("user")
    @NotNull
    @Expose
    private UserStartInfo user;

    @SerializedName("client")
    @NotNull
    @Expose
    private ClientStartInfo client;

    public StartResponse() {}

    public StartResponse(UserStartInfo user, ClientStartInfo client) {
        this.user = user;
        this.client = client;
    }

    public UserStartInfo getUser() {
        return user;
    }

    public ClientStartInfo getClient() {
        return client;
    }
}

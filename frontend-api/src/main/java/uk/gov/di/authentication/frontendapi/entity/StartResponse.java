package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.validation.Required;

public class StartResponse {

    @SerializedName("user")
    @Required
    @Expose
    private UserStartInfo user;

    @SerializedName("client")
    @Required
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

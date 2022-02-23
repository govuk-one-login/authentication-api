package uk.gov.di.authentication.frontendapi.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

public class StartResponse {

    @JsonProperty("user")
    private UserStartInfo user;

    @JsonProperty("client")
    private ClientStartInfo client;

    public StartResponse(
            @JsonProperty(required = true, value = "user") UserStartInfo user,
            @JsonProperty(required = true, value = "client") ClientStartInfo client) {
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

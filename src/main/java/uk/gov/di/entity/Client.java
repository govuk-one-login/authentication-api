package uk.gov.di.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public record Client(
        @JsonProperty("client_name") String clientName,
        @JsonProperty("client_id") String clientId,
        @JsonProperty("client_secret") String clientSecret,
        @JsonProperty("scopes")  List<String> scopes,
        @JsonIgnore  List<String> allowedResponseTypes,
        @JsonProperty("redirect_uris") List<String> redirectUrls,
        @JsonProperty("contacts") List<String> contacts) {}

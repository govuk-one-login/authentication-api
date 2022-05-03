package uk.gov.di.authentication.ipv.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

public enum SPOTStatus {
    @JsonProperty("Accepted")
    ACCEPTED,
    @JsonProperty("Rejected")
    REJECTED;
}

package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;

import java.util.Objects;

public record AccountInterventionsInboundResponse(
        @Expose Intervention intervention, @Expose State state) {
    public AccountInterventionsInboundResponse {
        Objects.requireNonNull(intervention);
        Objects.requireNonNull(state);
    }
}

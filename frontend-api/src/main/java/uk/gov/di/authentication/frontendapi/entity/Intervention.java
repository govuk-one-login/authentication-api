package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;

import java.util.Objects;

public record Intervention(@Expose Long appliedAt) {
    public Intervention {
        Objects.requireNonNull(appliedAt);
    }
}

package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import org.jetbrains.annotations.NotNull;

import java.util.Objects;

public record AuthCodeResponse(@Expose @NotNull String location) {
    public AuthCodeResponse {
        Objects.requireNonNull(location);
    }
}

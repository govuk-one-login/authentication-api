package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;

public record State(
        @Expose boolean blocked,
        @Expose boolean suspended,
        @Expose boolean reproveIdentity,
        @Expose boolean resetPassword) {}

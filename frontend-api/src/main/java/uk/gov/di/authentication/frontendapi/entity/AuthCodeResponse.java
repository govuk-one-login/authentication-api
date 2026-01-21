package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;

public record AuthCodeResponse(@Expose String location) {}

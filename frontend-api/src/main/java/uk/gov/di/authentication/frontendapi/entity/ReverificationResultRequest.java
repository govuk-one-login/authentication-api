package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import uk.gov.di.authentication.shared.validation.Required;

public record ReverificationResultRequest(@Expose @Required String code, @Expose String email) {}

package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import uk.gov.di.authentication.shared.validation.Required;

public record AMCCallbackRequest(@Expose @Required String code, @Expose @Required String state) {}

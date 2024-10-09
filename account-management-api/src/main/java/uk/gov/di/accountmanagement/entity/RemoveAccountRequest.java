package uk.gov.di.accountmanagement.entity;

import com.google.gson.annotations.Expose;
import uk.gov.di.authentication.shared.validation.Required;

public record RemoveAccountRequest(@Expose @Required String email) {}

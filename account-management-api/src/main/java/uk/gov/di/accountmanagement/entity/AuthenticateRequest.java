package uk.gov.di.accountmanagement.entity;

import com.google.gson.annotations.Expose;
import uk.gov.di.authentication.shared.validation.Required;

public record AuthenticateRequest(
        @Expose @Required String email, @Expose @Required String password) {}

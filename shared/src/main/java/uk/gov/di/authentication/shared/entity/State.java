package uk.gov.di.authentication.shared.entity;

import com.google.gson.annotations.Expose;
import uk.gov.di.authentication.shared.validation.Required;

public record State(
        @Expose @Required Boolean blocked,
        @Expose @Required Boolean suspended,
        @Expose @Required Boolean reproveIdentity,
        @Expose @Required Boolean resetPassword) {}

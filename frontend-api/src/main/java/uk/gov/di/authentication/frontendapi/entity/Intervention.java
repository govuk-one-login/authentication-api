package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import org.apache.logging.log4j.core.config.plugins.validation.constraints.Required;

public record Intervention(
        @Expose @Required String updatedAt,
        @Expose @Required String appliedAt,
        @Expose @Required String sentAt,
        @Expose @Required String description,
        @Expose @Required String reprovedIdentityAt,
        @Expose @Required String resetPasswordAt) {}

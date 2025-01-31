package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import org.apache.logging.log4j.core.config.plugins.validation.constraints.Required;

public record AccountInterventionsResponse(
        @Expose @Required boolean passwordResetRequired,
        @Expose @Required boolean blocked,
        @Expose @Required boolean temporarilySuspended,
        @Expose @Required boolean reproveIdentity,
        @Expose @Required Long appliedAt) {}

package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import org.apache.logging.log4j.core.config.plugins.validation.constraints.Required;

public record State(
        @Expose @Required boolean blocked,
        @Expose @Required boolean suspended,
        @Expose @Required boolean reproveIdentity,
        @Expose @Required boolean resetPassword) {}

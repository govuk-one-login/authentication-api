package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import org.apache.logging.log4j.core.config.plugins.validation.constraints.Required;

public record AuthCodeResponse(@Expose @Required String location) {}

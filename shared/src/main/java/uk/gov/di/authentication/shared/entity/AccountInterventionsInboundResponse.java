package uk.gov.di.authentication.shared.entity;

import com.google.gson.annotations.Expose;
import uk.gov.di.authentication.shared.validation.Required;

public record AccountInterventionsInboundResponse(
        @Expose @Required Intervention intervention, @Expose @Required State state) {}

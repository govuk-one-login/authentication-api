package uk.gov.di.authentication.frontendapi.entity.mfa;

import com.google.gson.annotations.Expose;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.validation.Required;

public record AuthAppMfaMethodResponse(
        @Expose @Required String id,
        @Expose @Required MFAMethodType type,
        @Expose @Required PriorityIdentifier priority)
        implements MfaMethodResponse {}

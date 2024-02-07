package uk.gov.di.accountmanagement.entity;

import com.google.gson.annotations.Expose;
import uk.gov.di.authentication.shared.validation.Required;

public record DeleteMfaMethodRequest(
        @Expose @Required String email,
        @Expose @Required String credential,
        @Expose @Required String otp) {}

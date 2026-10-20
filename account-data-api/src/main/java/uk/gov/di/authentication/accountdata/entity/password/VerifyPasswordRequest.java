package uk.gov.di.authentication.accountdata.entity.password;

import com.google.gson.annotations.Expose;
import uk.gov.di.authentication.shared.validation.Required;

public record VerifyPasswordRequest(@Expose @Required String password) {}
;

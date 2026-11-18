package uk.gov.di.authentication.frontendapi.entity;

import uk.gov.di.authentication.shared.helpers.Argon2HashParameters;

public record PasswordHashParametersOutcome(
        Argon2HashParameters currentParameters,
        boolean rehashed,
        Argon2HashParameters updatedParameters) {

    public static PasswordHashParametersOutcome notRehashed(
            Argon2HashParameters currentParameters) {
        return new PasswordHashParametersOutcome(currentParameters, false, null);
    }

    public static PasswordHashParametersOutcome rehashed(
            Argon2HashParameters currentParameters, Argon2HashParameters updatedParameters) {
        return new PasswordHashParametersOutcome(currentParameters, true, updatedParameters);
    }
}

package uk.gov.di.authentication.oidc.validators;

import uk.gov.di.authentication.oidc.entity.GlobalLogoutMessage;
import uk.gov.di.authentication.oidc.exceptions.GlobalLogoutValidationException;

import java.util.ArrayList;
import java.util.List;

public class GlobalLogoutValidator {
    private GlobalLogoutValidator() {}

    public static void validate(GlobalLogoutMessage message) {
        List<String> invalidFields = new ArrayList<>();
        if (message.clientId().isEmpty()) {
            invalidFields.add("clientId");
        }
        if (message.eventId().isEmpty()) {
            invalidFields.add("eventId");
        }
        if (message.sessionId().isEmpty()) {
            invalidFields.add("sessionId");
        }
        if (message.clientSessionId().isEmpty()) {
            invalidFields.add("clientSessionId");
        }
        if (message.internalCommonSubjectId().isEmpty()) {
            invalidFields.add("internalCommonSubjectId");
        }
        if (message.persistentSessionId().isEmpty()) {
            invalidFields.add("persistentSessionId");
        }
        if (message.ipAddress().isEmpty()) {
            invalidFields.add("ipAddress");
        }
        if (!invalidFields.isEmpty()) {
            throw new GlobalLogoutValidationException("Fields are empty strings: " + invalidFields);
        }
    }
}

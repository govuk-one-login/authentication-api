package uk.gov.di.authentication.shared.entity;

import com.google.gson.annotations.Expose;
import uk.gov.di.authentication.shared.validation.Required;

public record MfaMethodData(
        @Expose String mfaIdentifier,
        @Expose @Required PriorityIdentifier priorityIdentifier,
        @Expose @Required boolean methodVerified,
        @Expose @Required MfaDetail method) {
    public static MfaMethodData smsMethodData(
            String mfaIdentifier,
            PriorityIdentifier priorityIdentifier,
            boolean methodVerified,
            String phoneNumber) {
        return new MfaMethodData(
                mfaIdentifier,
                priorityIdentifier,
                methodVerified,
                new SmsMfaDetail(MFAMethodType.SMS, phoneNumber));
    }

    public static MfaMethodData authAppMfaData(
            String mfaIdentifier,
            PriorityIdentifier priorityIdentifier,
            boolean methodVerified,
            String credential) {
        return new MfaMethodData(
                mfaIdentifier,
                priorityIdentifier,
                methodVerified,
                new AuthAppMfaDetail(MFAMethodType.AUTH_APP, credential));
    }
}

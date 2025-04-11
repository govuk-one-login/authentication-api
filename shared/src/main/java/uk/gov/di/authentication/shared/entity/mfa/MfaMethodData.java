package uk.gov.di.authentication.shared.entity.mfa;

import com.google.gson.annotations.Expose;
import org.jetbrains.annotations.NotNull;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.validation.Required;

public record MfaMethodData(
        @Expose String mfaIdentifier,
        @Expose @Required PriorityIdentifier priorityIdentifier,
        @Expose @Required boolean methodVerified,
        @Expose @Required MfaDetail method)
        implements Comparable<MfaMethodData> {

    public static Result<String, MfaMethodData> from(MFAMethod mfaMethod) {
        if (mfaMethod.getMfaMethodType().equals(MFAMethodType.SMS.getValue())) {
            return Result.success(
                    smsMethodData(
                            mfaMethod.getMfaIdentifier(),
                            PriorityIdentifier.valueOf(mfaMethod.getPriority()),
                            mfaMethod.isMethodVerified(),
                            mfaMethod.getDestination()));
        } else if (mfaMethod.getMfaMethodType().equals(MFAMethodType.AUTH_APP.getValue())) {
            return Result.success(
                    authAppMfaData(
                            mfaMethod.getMfaIdentifier(),
                            PriorityIdentifier.valueOf(mfaMethod.getPriority()),
                            mfaMethod.isMethodVerified(),
                            mfaMethod.getCredentialValue()));
        } else {
            return Result.failure("Unsupported MFA method type: " + mfaMethod.getMfaMethodType());
        }
    }

    public static MfaMethodData smsMethodData(
            String mfaIdentifier,
            PriorityIdentifier priorityIdentifier,
            boolean methodVerified,
            String phoneNumber) {
        return new MfaMethodData(
                mfaIdentifier, priorityIdentifier, methodVerified, new SmsMfaDetail(phoneNumber));
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
                new AuthAppMfaDetail(credential));
    }

    @Override
    public int compareTo(@NotNull MfaMethodData other) {
        return this.mfaIdentifier.compareTo(other.mfaIdentifier);
    }
}

package uk.gov.di.authentication.shared.entity.mfa;

import com.google.gson.annotations.Expose;
import io.vavr.control.Either;
import org.jetbrains.annotations.NotNull;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.validation.Required;

public record MfaMethodData(
        @Expose String mfaIdentifier,
        @Expose @Required PriorityIdentifier priorityIdentifier,
        @Expose @Required boolean methodVerified,
        @Expose @Required MfaDetail method)
        implements Comparable<MfaMethodData> {

    public static Either<String, MfaMethodData> from(MFAMethod mfaMethod) {
        if (mfaMethod.getMfaMethodType().equals(MFAMethodType.SMS.getValue())) {
            return Either.right(
                    smsMethodData(
                            mfaMethod.getMfaIdentifier(),
                            PriorityIdentifier.valueOf(mfaMethod.getPriority()),
                            mfaMethod.isMethodVerified(),
                            mfaMethod.getDestination()));
        } else if (mfaMethod.getMfaMethodType().equals(MFAMethodType.AUTH_APP.getValue())) {
            return Either.right(
                    authAppMfaData(
                            mfaMethod.getMfaIdentifier(),
                            PriorityIdentifier.valueOf(mfaMethod.getPriority()),
                            mfaMethod.isMethodVerified(),
                            mfaMethod.getCredentialValue()));
        } else {
            return Either.left("Unsupported MFA method type: " + mfaMethod.getMfaMethodType());
        }
    }

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

    @Override
    public int compareTo(@NotNull MfaMethodData other) {
        return this.mfaIdentifier.compareTo(other.mfaIdentifier);
    }
}

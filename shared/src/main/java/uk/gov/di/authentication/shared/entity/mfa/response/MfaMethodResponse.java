package uk.gov.di.authentication.shared.entity.mfa.response;

import com.google.gson.annotations.Expose;
import org.jetbrains.annotations.NotNull;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.entity.mfa.MfaDetail;
import uk.gov.di.authentication.shared.validation.Required;

public record MfaMethodResponse(
        @Expose String mfaIdentifier,
        @Expose @Required PriorityIdentifier priorityIdentifier,
        @Expose @Required boolean methodVerified,
        @Expose @Required MfaDetail method)
        implements Comparable<MfaMethodResponse> {

    public static Result<String, MfaMethodResponse> from(MFAMethod mfaMethod) {
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

    public static MfaMethodResponse smsMethodData(
            String mfaIdentifier,
            PriorityIdentifier priorityIdentifier,
            boolean methodVerified,
            String phoneNumber) {
        return new MfaMethodResponse(
                mfaIdentifier,
                priorityIdentifier,
                methodVerified,
                new ResponseSmsMfaDetail(phoneNumber));
    }

    public static MfaMethodResponse authAppMfaData(
            String mfaIdentifier,
            PriorityIdentifier priorityIdentifier,
            boolean methodVerified,
            String credential) {
        return new MfaMethodResponse(
                mfaIdentifier,
                priorityIdentifier,
                methodVerified,
                new ResponseAuthAppMfaDetail(credential));
    }

    @Override
    public int compareTo(@NotNull MfaMethodResponse other) {
        return this.mfaIdentifier.compareTo(other.mfaIdentifier);
    }
}

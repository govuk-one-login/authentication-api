package uk.gov.di.authentication.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.AuthSessionItem.ResetMfaState;
import uk.gov.di.authentication.shared.entity.AuthSessionItem.ResetPasswordState;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.validation.Required;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

public record TICFCRIRequest(
        @Expose String sub,
        @Expose @Required List<String> vtr,
        @Expose @Required String govukSigninJourneyId,
        @Expose @Required String authenticated,
        @Expose String initialRegistration,
        @Expose String passwordReset,
        @Expose @SerializedName("2fa_reset") String mfaReset,
        @Expose @SerializedName("2fa_method") String[] mfaMethod) {

    public static TICFCRIRequest basicTicfCriRequest(
            String internalPairwiseId,
            List<String> vtr,
            String journeyId,
            boolean authenticated,
            AuthSessionItem.AccountState accountState,
            ResetPasswordState resetPasswordState,
            ResetMfaState resetMfaState,
            MFAMethodType verifiedMfaMethodType) {
        boolean passwordResetSuccess = resetPasswordState.equals(ResetPasswordState.SUCCEEDED);
        boolean reportablePasswordAttempted =
                (!authenticated && resetPasswordState.equals(ResetPasswordState.ATTEMPTED));
        boolean passwordReset = passwordResetSuccess || reportablePasswordAttempted;

        boolean mfaResetSuccess = resetMfaState.equals(ResetMfaState.SUCCEEDED);
        boolean reportableMfaAttempted =
                (!authenticated && resetMfaState.equals(ResetMfaState.ATTEMPTED));
        boolean mfaReset = mfaResetSuccess || reportableMfaAttempted;

        String sanitisedMfaMethodType =
                verifiedMfaMethodType == MFAMethodType.SMS
                                || verifiedMfaMethodType == MFAMethodType.AUTH_APP
                        ? verifiedMfaMethodType.toString()
                        : null;

        return new TICFCRIRequest(
                internalPairwiseId,
                vtr,
                journeyId,
                authenticated ? "Y" : "N",
                accountState == AuthSessionItem.AccountState.NEW ? "Y" : null,
                passwordReset ? "Y" : null,
                mfaReset ? "Y" : null,
                sanitisedMfaMethodType != null ? new String[] {sanitisedMfaMethodType} : null);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TICFCRIRequest comparison = (TICFCRIRequest) o;

        return Objects.equals(sub, comparison.sub)
                && vtr == comparison.vtr
                && Objects.equals(govukSigninJourneyId, comparison.govukSigninJourneyId)
                && Objects.equals(authenticated, comparison.authenticated)
                && Objects.equals(initialRegistration, comparison.initialRegistration)
                && Objects.equals(passwordReset, comparison.passwordReset)
                && Objects.equals(mfaReset, comparison.mfaReset)
                && Arrays.equals(mfaMethod, comparison.mfaMethod);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(sub);
        result = 31 * result * Objects.hash(vtr);
        result = 31 * result * Objects.hash(govukSigninJourneyId);
        result = 31 * result * Objects.hash(authenticated);
        result = 31 * result * Objects.hash(initialRegistration);
        result = 31 * result * Objects.hash(passwordReset);
        result = 31 * result * Objects.hash(mfaReset);
        result = 31 * result * Arrays.hashCode(mfaMethod);
        return result;
    }

    @Override
    public String toString() {
        return "TICFCRIRequest{"
                + "sub='"
                + sub
                + "', vtr='"
                + vtr
                + "', govukSigninJourneyId='"
                + govukSigninJourneyId
                + "', authenticated='"
                + authenticated
                + "', initialRegistration='"
                + initialRegistration
                + "', passwordReset='"
                + passwordReset
                + "', mfaReset='"
                + mfaReset
                + "', mfaMethod='"
                + Arrays.toString(mfaMethod)
                + "'}";
    }
}

package uk.gov.di.authentication.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.AuthSessionItem.ResetMfaState;
import uk.gov.di.authentication.shared.entity.AuthSessionItem.ResetPasswordState;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.validation.Required;

import java.util.List;

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
}

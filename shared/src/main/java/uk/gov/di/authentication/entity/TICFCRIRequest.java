package uk.gov.di.authentication.entity;

import com.google.gson.annotations.Expose;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.AuthSessionItem.ResetPasswordState;
import uk.gov.di.authentication.shared.validation.Required;

import java.util.List;

public record TICFCRIRequest(
        @Expose String sub,
        @Expose @Required List<String> vtr,
        @Expose @Required String govukSigninJourneyId,
        @Expose @Required String authenticated,
        @Expose String initialRegistration,
        @Expose String passwordReset) {

    public static TICFCRIRequest basicTicfCriRequest(
            String internalPairwiseId,
            List<String> vtr,
            String journeyId,
            boolean authenticated,
            AuthSessionItem.AccountState accountState,
            ResetPasswordState resetPasswordState) {
        boolean passwordResetSuccess = resetPasswordState.equals(ResetPasswordState.SUCCEEDED);
        boolean reportablePasswordAttempted =
                (!authenticated && resetPasswordState.equals(ResetPasswordState.ATTEMPTED));
        boolean passwordReset = passwordResetSuccess || reportablePasswordAttempted;

        return new TICFCRIRequest(
                internalPairwiseId,
                vtr,
                journeyId,
                authenticated ? "Y" : "N",
                accountState == AuthSessionItem.AccountState.NEW ? "Y" : null,
                passwordReset ? "Y" : null);
    }
}

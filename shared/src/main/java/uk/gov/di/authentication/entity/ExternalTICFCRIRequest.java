package uk.gov.di.authentication.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.AuthSessionItem.ResetMfaState;
import uk.gov.di.authentication.shared.entity.AuthSessionItem.ResetPasswordState;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.validation.Required;

import java.util.Collections;
import java.util.List;

public record ExternalTICFCRIRequest(
        @Expose String sub,
        @Expose @Required List<String> vtr,
        @Expose @SerializedName("govuk_signin_journey_id") @Required String govukSigninJourneyId,
        @Expose @Required String authenticated,
        @Expose @SerializedName("initial_registration") String initialRegistration,
        @Expose @SerializedName("password_reset") String passwordReset,
        @Expose @SerializedName("2fa_reset") String mfaReset,
        @Expose @SerializedName("2fa_method") List<String> mfaMethod) {

    public static ExternalTICFCRIRequest fromInternalRequest(
            InternalTICFCRIRequest internalRequest) {
        boolean passwordResetSuccess =
                internalRequest.resetPasswordState().equals(ResetPasswordState.SUCCEEDED);
        boolean reportablePasswordAttempted =
                (!internalRequest.authenticated()
                        && internalRequest
                                .resetPasswordState()
                                .equals(ResetPasswordState.ATTEMPTED));
        boolean passwordReset = passwordResetSuccess || reportablePasswordAttempted;

        boolean mfaResetSuccess = internalRequest.resetMfaState().equals(ResetMfaState.SUCCEEDED);
        boolean reportableMfaAttempted =
                (!internalRequest.authenticated()
                        && internalRequest.resetMfaState().equals(ResetMfaState.ATTEMPTED));
        boolean mfaReset = mfaResetSuccess || reportableMfaAttempted;

        String sanitisedMfaMethodType =
                internalRequest.mfaMethodType() == MFAMethodType.SMS
                                || internalRequest.mfaMethodType() == MFAMethodType.AUTH_APP
                        ? internalRequest.mfaMethodType().toString()
                        : null;

        return new ExternalTICFCRIRequest(
                internalRequest.internalCommonSubjectIdentifier(),
                internalRequest.vtr(),
                internalRequest.govukSigninJourneyId(),
                internalRequest.authenticated() ? "Y" : "N",
                internalRequest.accountState() == AuthSessionItem.AccountState.NEW ? "Y" : null,
                passwordReset ? "Y" : null,
                mfaReset ? "Y" : null,
                sanitisedMfaMethodType != null
                        ? Collections.singletonList(sanitisedMfaMethodType)
                        : null);
    }

    @Override
    public String toString() {
        return "TICFCRIRequest{"
                + "internalCommonSubjectIdentifier='"
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
                + mfaMethod
                + "'}";
    }
}

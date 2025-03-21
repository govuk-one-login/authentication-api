package uk.gov.di.authentication.entity;

import com.google.gson.annotations.Expose;
import uk.gov.di.authentication.shared.entity.AuthSessionItem.AccountState;
import uk.gov.di.authentication.shared.entity.AuthSessionItem.ResetMfaState;
import uk.gov.di.authentication.shared.entity.AuthSessionItem.ResetPasswordState;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;

import java.util.List;

public record InternalTICFCRIRequest(
        @Expose String internalCommonSubjectIdentifier,
        @Expose List<String> vtr,
        @Expose String govukSigninJourneyId,
        @Expose boolean authenticated,
        @Expose AccountState accountState,
        @Expose ResetPasswordState resetPasswordState,
        @Expose ResetMfaState resetMfaState,
        MFAMethodType mfaMethodType) {}

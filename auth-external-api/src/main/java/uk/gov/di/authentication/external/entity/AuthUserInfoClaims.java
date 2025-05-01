package uk.gov.di.authentication.external.entity;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

public enum AuthUserInfoClaims {
    LEGACY_SUBJECT_ID("legacy_subject_id"),
    PUBLIC_SUBJECT_ID("public_subject_id"),
    LOCAL_ACCOUNT_ID("local_account_id"),
    EMAIL("email"),
    EMAIL_VERIFIED("email_verified"),
    PHONE_NUMBER("phone_number"),
    PHONE_VERIFIED("phone_number_verified"),
    SALT("salt"),
    VERIFIED_MFA_METHOD_TYPE("verified_mfa_method_type"),
    CURRENT_CREDENTIAL_STRENGTH("current_credential_strength"),
    NEW_ACCOUNT("new_account"),
    UPLIFT_REQUIRED("uplift_required"),
    ACHIEVED_CREDENTIAL_STRENGTH("achieved_credential_strength");

    private final String value;

    AuthUserInfoClaims(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    public static Set<String> getAllValidClaims() {
        return Arrays.stream(AuthUserInfoClaims.values())
                .map(AuthUserInfoClaims::getValue)
                .collect(Collectors.toSet());
    }

    public static boolean isValidClaim(String claim) {
        return Arrays.stream(AuthUserInfoClaims.values())
                .map(AuthUserInfoClaims::getValue)
                .anyMatch(t -> t.equals(claim));
    }
}

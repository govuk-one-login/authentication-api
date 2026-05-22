package uk.gov.di.accountmanagement.entity;

public enum PasskeysDeleteProxyFailureReason {
    FAILED_TO_DELETE_PASSKEY("failed_to_delete_passkey"),
    FAILED_TO_RETRIEVE_PASSKEY_COUNT("failed_to_retrieve_passkey_count"),
    FAILED_TO_FIND_USER_PROFILE("failed_to_find_user_profile");

    private final String value;

    PasskeysDeleteProxyFailureReason(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}

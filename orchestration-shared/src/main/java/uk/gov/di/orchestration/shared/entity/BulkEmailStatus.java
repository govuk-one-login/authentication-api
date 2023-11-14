package uk.gov.di.orchestration.shared.entity;

public enum BulkEmailStatus {
    PENDING("PENDING"),
    EMAIL_SENT("EMAIL_SENT"),
    ACCOUNT_NOT_FOUND("ACCOUNT_NOT_FOUND"),
    ERROR_SENDING_EMAIL("ERROR_SENDING_EMAIL"),
    TERMS_ACCEPTED_RECENTLY("TERMS_ACCEPTED_RECENTLY"),
    RETRY_EMAIL_SENT("RETRY_EMAIL_SENT");

    private String value;

    BulkEmailStatus(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}

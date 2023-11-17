package uk.gov.di.orchestration.shared.entity;

public enum BulkEmailUserSendMode {
    PENDING("PENDING"),
    NOTIFY_ERROR_RETRIES("NOTIFY_ERROR_RETRIES"),
    DELIVERY_RECEIPT_TEMPORARY_FAILURE_RETRIES("DELIVERY_RECEIPT_TEMPORARY_FAILURE_RETRIES");

    private String value;

    BulkEmailUserSendMode(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    public BulkEmailStatus mapToSuccessStatus() {
        return DELIVERY_RECEIPT_TEMPORARY_FAILURE_RETRIES.equals(this)
                ? BulkEmailStatus.RETRY_EMAIL_SENT
                : BulkEmailStatus.EMAIL_SENT;
    }
}

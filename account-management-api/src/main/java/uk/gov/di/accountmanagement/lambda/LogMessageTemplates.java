package uk.gov.di.accountmanagement.lambda;

public class LogMessageTemplates {
    public static final String NOTIFY_TEST_DESTINATION_USED_WRITING_TO_S3_BUCKET =
            "Notify Test Destination used in request. Writing to S3 bucket for notification type {}";
    public static final String NOT_WRITING_TO_BUCKET_AS_NOT_OTP_NOTIFICATION =
            "Not writing to bucket as notification type {} is not an otp notification type.";
    public static final String WRITING_OTP_TO_S_3_BUCKET = "Writing OTP to S3 bucket: {}";

    private LogMessageTemplates() {}

    public static final String ERROR_SENDING_WITH_NOTIFY = "Error sending with Notify: {}";
    public static final String UNEXPECTED_ERROR_SENDING_NOTIFICATION =
            "Unexpected error sending {} notification {}";
    public static final String TEXT_HAS_BEEN_SENT_USING_NOTIFY =
            "{} text has been sent using Notify";
    public static final String EMAIL_HAS_BEEN_SENT_USING_NOTIFY =
            "{} email has been sent using Notify";
    public static final String CONTACT_US_LINK_PERSONALISATION = "contact-us-link";
    public static final String MESSAGE_RECEIVED_FROM_SQS_QUEUE = "Message received from SQS queue";
    public static final String ERROR_WHEN_MAPPING_MESSAGE_FROM_QUEUE_TO_A_NOTIFY_REQUEST =
            "Error when mapping message from queue to a NotifyRequest";
}

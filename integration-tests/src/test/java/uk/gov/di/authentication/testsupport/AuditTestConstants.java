package uk.gov.di.authentication.testsupport;

public interface AuditTestConstants {
    String INTERNAL_SUBJECT_ID = "extensions.internalSubjectId";
    String INCORRECT_PASSWORD_COUNT = "extensions.incorrectPasswordCount";
    String ATTEMPT_NO_FAILED_AT = "extensions.attemptNoFailedAt";
    String INCORRECT_EMAIL_ATTEMPT_COUNT = "extensions.incorrect_email_attempt_count";
    String INCORRECT_OTP_CODE_ATTEMPT_COUNT = "extensions.incorrect_otp_code_attempt_count";
    String INCORRECT_PASSWORD_ATTEMPT_COUNT = "extensions.incorrect_password_attempt_count";
    String FAILURE_REASON = "extensions.failure-reason";
    String RP_PAIRWISE_ID = "extensions.rpPairwiseId";
    String NUMBER_OF_ATTEMPTS_USER_ALLOWED_TO_LOGIN =
            "extensions.number_of_attempts_user_allowed_to_login";
    String USER_SUPPLIED_EMAIL = "restricted.user_supplied_email";
    String USER_ID_FOR_USER_SUPPLIED_EMAIL = "restricted.user_id_for_user_supplied_email";
}

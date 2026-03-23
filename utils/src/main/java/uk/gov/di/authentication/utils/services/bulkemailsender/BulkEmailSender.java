package uk.gov.di.authentication.utils.services.bulkemailsender;

import uk.gov.di.authentication.shared.entity.BulkEmailStatus;
import uk.gov.di.authentication.shared.entity.BulkEmailUserSendMode;

public interface BulkEmailSender {

    void validateConfiguration();

    void validateAndSendMessage(String subjectId, BulkEmailUserSendMode sendMode);

    void updateBulkUserStatus(String subjectId, BulkEmailStatus bulkEmailStatus);
}

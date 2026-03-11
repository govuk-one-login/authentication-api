package uk.gov.di.authentication.utils.services.bulkemailsender;

import uk.gov.di.authentication.shared.entity.BulkEmailStatus;

public interface BulkEmailSender {

    void updateBulkUserStatus(String subjectId, BulkEmailStatus bulkEmailStatus);
}

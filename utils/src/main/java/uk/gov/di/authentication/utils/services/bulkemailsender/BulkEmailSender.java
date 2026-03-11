package uk.gov.di.authentication.utils.services.bulkemailsender;

import uk.gov.di.authentication.shared.entity.BulkEmailStatus;
import uk.gov.di.authentication.shared.entity.UserProfile;

public interface BulkEmailSender {

    boolean validateUser(UserProfile userProfile);

    void updateBulkUserStatus(String subjectId, BulkEmailStatus bulkEmailStatus);
}

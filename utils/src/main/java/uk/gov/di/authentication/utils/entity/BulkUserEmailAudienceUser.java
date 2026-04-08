package uk.gov.di.authentication.utils.entity;

import com.google.gson.annotations.Expose;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;

public record BulkUserEmailAudienceUser(@Expose String email, @Expose String subjectID) {
    public static BulkUserEmailAudienceUser from(Object item) {
        String email, subjectID;

        if (item instanceof UserProfile user) {
            email = user.getEmail();
            subjectID = user.getSubjectID();
        } else if (item instanceof UserCredentials user) {
            email = user.getEmail();
            subjectID = user.getSubjectID();
        } else {
            throw new IllegalArgumentException(
                    "Unsupported type: " + (item == null ? "null" : item.getClass().getName()));
        }

        return new BulkUserEmailAudienceUser(email, subjectID);
    }
}

package uk.gov.di.authentication.external.helpers;

import com.nimbusds.oauth2.sdk.id.Subject;
import uk.gov.di.authentication.shared.entity.UserProfile;

import java.nio.ByteBuffer;

public class CommonTestVariables {

    public static final String TEST_LEGACY_SUBJECT_ID = "test-legacy-subject-id";
    public static final String TEST_PUBLIC_SUBJECT_ID = "test-public-subject-id";
    public static final Subject TEST_INTERNAL_PAIRWISE_ID = new Subject();
    public static final Subject TEST_SUBJECT = new Subject();
    public static final String TEST_EMAIL = "test-email";
    public static final boolean TEST_EMAIL_VERIFIED = true;
    public static final String TEST_PHONE = "test-phone";
    public static final boolean TEST_PHONE_VERIFIED = true;
    public static final ByteBuffer TEST_SALT = ByteBuffer.allocate(10);
    public static final String TEST_INTERNAL_SECTOR_URI = "https://test-internal-sector-uri";

    public static UserProfile generateUserProfile() {
        return new UserProfile()
                .withLegacySubjectID(TEST_LEGACY_SUBJECT_ID)
                .withPublicSubjectID(TEST_PUBLIC_SUBJECT_ID)
                .withSubjectID(TEST_SUBJECT.getValue())
                .withEmail(TEST_EMAIL)
                .withEmailVerified(TEST_EMAIL_VERIFIED)
                .withPhoneNumber(TEST_PHONE)
                .withPhoneNumberVerified(TEST_PHONE_VERIFIED)
                .withSalt(TEST_SALT);
    }
}

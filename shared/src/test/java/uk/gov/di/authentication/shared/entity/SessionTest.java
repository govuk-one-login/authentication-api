package uk.gov.di.authentication.shared.entity;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_EMAIL;

class SessionTest {
    private final Session session = new Session().setEmailAddress("joe.bloggs@test.com");

    @RegisterExtension
    private final CaptureLoggingExtension logging = new CaptureLoggingExtension(Session.class);

    @Test
    void invalidNotificationJourneyComboShouldNotAddNullValuesToSession() {
        try {
            session.incrementCodeRequestCount(VERIFY_EMAIL, JourneyType.SIGN_IN);
            assertThat(session.getCodeRequestCount(null), equalTo(0));
        } catch (Exception e) {
        }
    }
}

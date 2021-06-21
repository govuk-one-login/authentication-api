package uk.gov.di.authentication.queuehandlers;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.helpers.httpstub.HttpStubExtension;

public class SendEmailNotificationIntegrationTest {

    @RegisterExtension
    private final HttpStubExtension notifyStub = new HttpStubExtension();

    @Test
    void shouldCallNotifyWhenValidRequestIsAddedToQueue () {

    }
}

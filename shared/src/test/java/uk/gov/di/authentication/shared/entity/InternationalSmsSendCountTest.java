package uk.gov.di.authentication.shared.entity;

import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

class InternationalSmsSendCountTest {

    private static final String PHONE_NUMBER = "+33777777777";
    private static final int SENT_COUNT = 7;

    @Test
    void shouldCreateUserCredentials() {
        InternationalSmsSendCount internationalSmsSendCount = generateInternationalSmsCount();

        assertThat(internationalSmsSendCount.getPhoneNumber(), equalTo(PHONE_NUMBER));
        assertThat(internationalSmsSendCount.getSentCount(), equalTo(SENT_COUNT));
    }

    private InternationalSmsSendCount generateInternationalSmsCount() {
        return new InternationalSmsSendCount()
                .withPhoneNumber(PHONE_NUMBER)
                .withSentCount(SENT_COUNT);
    }
}

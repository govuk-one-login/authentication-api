package uk.gov.di.audit;

import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.domain.AuditableEvent;
import uk.gov.di.authentication.shared.helpers.NowHelper;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static uk.gov.di.audit.TxmaAuditPayload.auditEventWithTime;
import static uk.gov.di.audit.TxmaAuditPayloadTest.TestAuditableEvent.TEST_EVENT;
import static uk.gov.di.authentication.sharedtest.matchers.JsonMatcher.asJson;
import static uk.gov.di.authentication.sharedtest.matchers.JsonMatcher.hasFieldWithValue;
import static uk.gov.di.authentication.sharedtest.matchers.JsonMatcher.hasNumericFieldWithValue;

class TxmaAuditPayloadTest {

    enum TestAuditableEvent implements AuditableEvent {
        TEST_EVENT;

        @Override
        public AuditableEvent parseFromName(String name) {
            return TEST_EVENT;
        }
    }

    @Test
    void shouldSerializeEventWithMandatoryFields() {
        var now = NowHelper.now();

        var payload = asJson(auditEventWithTime(TEST_EVENT, () -> now).serialize());

        assertThat(payload, hasFieldWithValue("event_name", is("AUTH_TEST_EVENT")));
        assertThat(payload, hasNumericFieldWithValue("timestamp", is(now.getTime())));
    }
}

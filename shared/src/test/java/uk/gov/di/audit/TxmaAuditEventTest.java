package uk.gov.di.audit;

import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.domain.AuditableEvent;
import uk.gov.di.authentication.shared.helpers.NowHelper;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static uk.gov.di.audit.TxmaAuditEvent.auditEvent;
import static uk.gov.di.audit.TxmaAuditEvent.auditEventWithTime;
import static uk.gov.di.audit.TxmaAuditEventTest.TestAuditableEvent.TEST_EVENT;
import static uk.gov.di.authentication.sharedtest.matchers.JsonMatcher.asJson;
import static uk.gov.di.authentication.sharedtest.matchers.JsonMatcher.hasFieldWithValue;
import static uk.gov.di.authentication.sharedtest.matchers.JsonMatcher.hasNumericFieldWithValue;

class TxmaAuditEventTest {

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

    @Test
    void shouldSerializeEventWithNonMandatoryFields() {
        var event =
                auditEvent(TEST_EVENT)
                        .withClientId("client-id")
                        .withComponentName("component-name");

        var payload = asJson(event.serialize());

        assertThat(payload, hasFieldWithValue("client_id", is("client-id")));
        assertThat(payload, hasFieldWithValue("component_name", is("component-name")));
    }

    @Test
    void shouldSerializeUserSubObject() {
        var user =
                TxmaAuditUser.user()
                        .withUserId("user-id")
                        .withEmail("email")
                        .withIpAddress("ip-address")
                        .withPersistentSessionId("persistent-id")
                        .withPhone("01110")
                        .withSessionId("session-id")
                        .withTransactionId("transaction-id")
                        .withGovukSigninJourneyId("journey-id");

        var event = auditEvent(TEST_EVENT).withUser(user);

        var payload = asJson(event.serialize()).getAsJsonObject().get("user");

        assertThat(payload, hasFieldWithValue("user_id", is("user-id")));
        assertThat(payload, hasFieldWithValue("email", is("email")));
        assertThat(payload, hasFieldWithValue("ip_address", is("ip-address")));
        assertThat(payload, hasFieldWithValue("persistent_session_id", is("persistent-id")));
        assertThat(payload, hasFieldWithValue("phone", is("01110")));
        assertThat(payload, hasFieldWithValue("session_id", is("session-id")));
        assertThat(payload, hasFieldWithValue("transaction_id", is("transaction-id")));
        assertThat(payload, hasFieldWithValue("govuk_signin_journey_id", is("journey-id")));
    }
}

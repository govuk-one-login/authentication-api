package uk.gov.di.audit;

import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.domain.AuditableEvent;
import uk.gov.di.authentication.shared.helpers.NowHelper;

import java.util.Map;

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
        assertThat(
                payload,
                hasNumericFieldWithValue("timestamp", is(now.toInstant().getEpochSecond())));
    }

    @Test
    void shouldSerializeEventWithNonMandatoryFields() {
        var event =
                auditEvent(TEST_EVENT).withClientId("client-id").withComponentId("component-id");

        var payload = asJson(event.serialize());

        assertThat(payload, hasFieldWithValue("client_id", is("client-id")));
        assertThat(payload, hasFieldWithValue("component_id", is("component-id")));
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

    @Test
    void shouldSerializeRestrictedSubObject() {
        var event =
                auditEvent(TEST_EVENT)
                        .addRestricted("key1", "value1")
                        .addRestricted("key2", 2)
                        .addRestricted("sub-object", Map.of("key3", "value3"));

        var payload = asJson(event.serialize()).getAsJsonObject().get("restricted");

        assertThat(payload, hasFieldWithValue("key1", is("value1")));
        assertThat(payload, hasNumericFieldWithValue("key2", is(2L)));

        var subObject = payload.getAsJsonObject().get("sub-object");

        assertThat(subObject, hasFieldWithValue("key3", is("value3")));
    }

    @Test
    void shouldSerializePlatformSubObject() {
        var event =
                auditEvent(TEST_EVENT)
                        .addPlatform("key1", "value1")
                        .addPlatform("key2", 2)
                        .addPlatform("sub-object", Map.of("key3", "value3"));

        var payload = asJson(event.serialize()).getAsJsonObject().get("platform");

        assertThat(payload, hasFieldWithValue("key1", is("value1")));
        assertThat(payload, hasNumericFieldWithValue("key2", is(2L)));

        var subObject = payload.getAsJsonObject().get("sub-object");

        assertThat(subObject, hasFieldWithValue("key3", is("value3")));
    }

    @Test
    void shouldSerializeExtensionsSubObject() {
        var event =
                auditEvent(TEST_EVENT)
                        .addExtension("key1", "value1")
                        .addExtension("key2", 2)
                        .addExtension("sub-object", Map.of("key3", "value3"));

        var payload = asJson(event.serialize()).getAsJsonObject().get("extensions");

        assertThat(payload, hasFieldWithValue("key1", is("value1")));
        assertThat(payload, hasNumericFieldWithValue("key2", is(2L)));

        var subObject = payload.getAsJsonObject().get("sub-object");

        assertThat(subObject, hasFieldWithValue("key3", is("value3")));
    }
}

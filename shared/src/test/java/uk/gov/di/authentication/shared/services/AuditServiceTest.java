package uk.gov.di.authentication.shared.services;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.shared.domain.AuditableEvent;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.authentication.shared.services.AuditServiceTest.TestEvents.TEST_EVENT_ONE;
import static uk.gov.di.authentication.sharedtest.matchers.JsonMatcher.asJson;
import static uk.gov.di.authentication.sharedtest.matchers.JsonMatcher.hasFieldWithValue;
import static uk.gov.di.authentication.sharedtest.matchers.JsonMatcher.hasNumericFieldWithValue;

class AuditServiceTest {

    private static final String FIXED_TIMESTAMP = "2021-09-01T22:10:00.012Z";
    private static final Clock FIXED_CLOCK =
            Clock.fixed(Instant.parse(FIXED_TIMESTAMP), ZoneId.of("UTC"));

    private final AwsSqsClient awsSqsClient = mock(AwsSqsClient.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);

    private final ArgumentCaptor<String> txmaMessageCaptor = ArgumentCaptor.forClass(String.class);

    enum TestEvents implements AuditableEvent {
        TEST_EVENT_ONE;

        public AuditableEvent parseFromName(String name) {
            return valueOf(name);
        }
    }

    @Test
    void shouldLogAuditEvent() {
        var auditService = new AuditService(FIXED_CLOCK, configurationService, awsSqsClient);

        auditService.submitAuditEvent(
                TEST_EVENT_ONE,
                new AuditContext(
                        "client-id",
                        "request-id",
                        "session-id",
                        "subject-id",
                        "email",
                        "ip-address",
                        "phone-number",
                        "persistent-session-id"));

        verify(awsSqsClient).send(txmaMessageCaptor.capture());

        var txmaMessage = asJson(txmaMessageCaptor.getValue());

        assertThat(txmaMessage, hasFieldWithValue("event_name", equalTo("AUTH_TEST_EVENT_ONE")));
        assertThat(txmaMessage, hasNumericFieldWithValue("timestamp", equalTo(1630534200L)));
        assertThat(txmaMessage, hasFieldWithValue("client_id", equalTo("client-id")));
        assertThat(txmaMessage, hasFieldWithValue("component_id", equalTo("AUTH")));

        var userObject = txmaMessage.getAsJsonObject().get("user").getAsJsonObject();

        assertThat(userObject, hasFieldWithValue("session_id", equalTo("session-id")));
        assertThat(
                userObject,
                hasFieldWithValue("persistent_session_id", equalTo("persistent-session-id")));
        assertThat(userObject, hasFieldWithValue("user_id", equalTo("subject-id")));
        assertThat(userObject, hasFieldWithValue("email", equalTo("email")));
        assertThat(userObject, hasFieldWithValue("phone", equalTo("phone-number")));
        assertThat(userObject, hasFieldWithValue("ip_address", equalTo("ip-address")));
    }

    @Test
    void shouldLogAuditEventWithMetadataPairsAttached() {
        var auditService = new AuditService(FIXED_CLOCK, configurationService, awsSqsClient);

        auditService.submitAuditEvent(
                TEST_EVENT_ONE,
                "client-id",
                "request-id",
                "session-id",
                "subject-id",
                "email",
                "ip-address",
                "phone-number",
                "persistent-session-id",
                pair("key", "value"),
                pair("key2", "value2"));

        verify(awsSqsClient).send(txmaMessageCaptor.capture());
        var txmaMessage = asJson(txmaMessageCaptor.getValue());

        assertThat(txmaMessage, hasFieldWithValue("event_name", equalTo("AUTH_TEST_EVENT_ONE")));
        assertThat(txmaMessage, hasNumericFieldWithValue("timestamp", equalTo(1630534200L)));

        var extensions = txmaMessage.getAsJsonObject().get("extensions").getAsJsonObject();

        assertThat(extensions, hasFieldWithValue("key", equalTo("value")));
        assertThat(extensions, hasFieldWithValue("key2", equalTo("value2")));
    }

    @Test
    void shouldAddCountryCodeExtensionToPhoneNumberEvents() {
        var auditService = new AuditService(FIXED_CLOCK, configurationService, awsSqsClient);

        auditService.submitAuditEvent(
                TEST_EVENT_ONE,
                "client-id",
                "request-id",
                "session-id",
                "subject-id",
                "email",
                "ip-address",
                "07700900000",
                "persistent-session-id",
                pair("key", "value"),
                pair("key2", "value2"));

        verify(awsSqsClient).send(txmaMessageCaptor.capture());

        var extensions =
                asJson(txmaMessageCaptor.getValue())
                        .getAsJsonObject()
                        .get("extensions")
                        .getAsJsonObject();

        assertThat(extensions, hasFieldWithValue("phone_number_country_code", equalTo("44")));
    }
}

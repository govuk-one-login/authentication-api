package uk.gov.di.authentication.shared.services;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.shared.domain.AuditableEvent;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Optional;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.authentication.shared.services.AuditServiceTest.TestEvents.AUTH_TEST_EVENT_ONE;
import static uk.gov.di.authentication.sharedtest.matchers.JsonMatcher.asJson;
import static uk.gov.di.authentication.sharedtest.matchers.JsonMatcher.hasField;
import static uk.gov.di.authentication.sharedtest.matchers.JsonMatcher.hasFieldWithValue;
import static uk.gov.di.authentication.sharedtest.matchers.JsonMatcher.hasNumericFieldWithValue;

class AuditServiceTest {

    public static final String ENCODED_DEVICE_INFORMATION =
            "R21vLmd3QilNKHJsaGkvTFxhZDZrKF44SStoLFsieG0oSUY3aEhWRVtOMFRNMVw1dyInKzB8OVV5N09hOi8kLmlLcWJjJGQiK1NPUEJPPHBrYWJHP358NDg2ZDVc";
    private static final String FIXED_TIMESTAMP = "2021-09-01T22:10:00.012Z";
    private static final Clock FIXED_CLOCK =
            Clock.fixed(Instant.parse(FIXED_TIMESTAMP), ZoneId.of("UTC"));

    private final AwsSqsClient awsSqsClient = mock(AwsSqsClient.class);

    private final ArgumentCaptor<String> txmaMessageCaptor = ArgumentCaptor.forClass(String.class);

    private static final AuditContext AUDIT_CONTEXT =
            new AuditContext(
                    "client-id",
                    "request-id",
                    "session-id",
                    "subject-id",
                    "email",
                    "ip-address",
                    "phone-number",
                    "persistent-session-id",
                    Optional.empty(),
                    new ArrayList<>());

    enum TestEvents implements AuditableEvent {
        AUTH_TEST_EVENT_ONE;

        public AuditableEvent parseFromName(String name) {
            return valueOf(name);
        }
    }

    private AuditService auditService;

    @BeforeEach
    void beforeEach() {
        auditService = new AuditService(FIXED_CLOCK, awsSqsClient);
    }

    @Test
    void shouldLogAuditEvent() {
        var myContext =
                new AuditContext(
                        "client-id",
                        "request-id",
                        "session-id",
                        "subject-id",
                        "email",
                        "ip-address",
                        "phone-number",
                        "persistent-session-id",
                        Optional.empty(),
                        new ArrayList<>());

        auditService.submitAuditEvent(AUTH_TEST_EVENT_ONE, myContext);

        verify(awsSqsClient).send(txmaMessageCaptor.capture());

        var txmaMessage = asJson(txmaMessageCaptor.getValue());

        var expected =
                """
                {
                "timestamp":1630534200,
                "event_timestamp_ms":1630534200012,
                "event_name":"AUTH_TEST_EVENT_ONE",
                "client_id":"client-id",
                "component_id":"AUTH",
                "user": {
                    "user_id":"subject-id",
                    "transaction_id":null,
                    "email":"email",
                    "phone":"phone-number",
                    "ip_address":"ip-address",
                    "session_id":"session-id",
                    "persistent_session_id":"persistent-session-id",
                    "govuk_signin_journey_id":"request-id"
                },
                "platform":null,
                "restricted":null,
                "extensions":null}
                """;

        assertEquals(asJson(expected), txmaMessage);
    }

    @Test
    void shouldLogAuditEventWithMetadataPairsAttached() {
        auditService.submitAuditEvent(
                AUTH_TEST_EVENT_ONE,
                AUDIT_CONTEXT,
                pair("key", "value"),
                pair("key2", "value2"),
                pair("restrictedKey1", "restrictedValue1", true),
                pair("restrictedKey2", "restrictedValue2", true));

        verify(awsSqsClient).send(txmaMessageCaptor.capture());
        var txmaMessage = asJson(txmaMessageCaptor.getValue());

        assertThat(txmaMessage, hasFieldWithValue("event_name", equalTo("AUTH_TEST_EVENT_ONE")));
        assertThat(txmaMessage, hasNumericFieldWithValue("timestamp", equalTo(1630534200L)));

        var extensions = txmaMessage.getAsJsonObject().get("extensions").getAsJsonObject();

        assertThat(extensions, hasFieldWithValue("key", equalTo("value")));
        assertThat(extensions, hasFieldWithValue("key2", equalTo("value2")));

        var restricted = txmaMessage.getAsJsonObject().get("restricted").getAsJsonObject();

        assertThat(restricted, hasFieldWithValue("restrictedKey1", equalTo("restrictedValue1")));
        assertThat(restricted, hasFieldWithValue("restrictedKey2", equalTo("restrictedValue2")));
    }

    @Test
    void shouldAddCountryCodeExtensionToPhoneNumberEvents() {

        auditService.submitAuditEvent(
                AUTH_TEST_EVENT_ONE,
                AUDIT_CONTEXT.withPhoneNumber("07700900000"),
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

    @Test
    void txmaHeaderShouldBeAddedToAuditEvent() {
        var auditEncodedHeaderValue =
                "R21vLmd3QilNKHJsaGkvTFxhZDZrKF44SStoLFsieG0oSUY3aEhWRVtOMFRNMVw1dyInKzB8OVV5N09hOi8kLmlLcWJjJGQiK1NPUEJPPHBrYWJHP358NDg2ZDVc";

        auditService.submitAuditEvent(
                AUTH_TEST_EVENT_ONE,
                AUDIT_CONTEXT.withTxmaAuditEncoded(Optional.of(auditEncodedHeaderValue)),
                pair("restrictedKey1", "restrictedValue1", true));

        verify(awsSqsClient).send(txmaMessageCaptor.capture());
        assertThatTheRestrictedDataPairsAreWrittenToTheRestrictedSection();
        assertThatTheDeviceInformationIsWrittenToTheRestrictedSection();
    }

    @Test
    void anEmptyTXMAHeaderShouldNotBeAddedToAuditEventWhenNoOtherRestrictedData() {
        auditService.submitAuditEvent(
                AUTH_TEST_EVENT_ONE, AUDIT_CONTEXT.withTxmaAuditEncoded(Optional.empty()));

        verify(awsSqsClient).send(txmaMessageCaptor.capture());
        assertThatTheRestrictedSectionDoesNotExist();
    }

    @Test
    void anEmptyTXMAHeaderShouldNotBeAddedToAuditEventWhenOtherRestrictedDataHasBeenWritten() {
        auditService.submitAuditEvent(
                AUTH_TEST_EVENT_ONE,
                AUDIT_CONTEXT.withTxmaAuditEncoded(Optional.empty()),
                pair("restrictedKey1", "restrictedValue1", true));

        verify(awsSqsClient).send(txmaMessageCaptor.capture());
        assertThatTheRestrictedSectionDoesNotContainADeviceInformationObject();
    }

    @Test
    void populatesExtensionsFromAuditContext() {
        var context = AUDIT_CONTEXT.withMetadataItem(pair("mfa-method", "DEFAULT", false));

        auditService.submitAuditEvent(AUTH_TEST_EVENT_ONE, context);

        verify(awsSqsClient).send(txmaMessageCaptor.capture());

        var txmaMessage = asJson(txmaMessageCaptor.getValue());
        System.out.println("audit event: " + txmaMessage);

        var extensions = txmaMessage.getAsJsonObject().get("extensions");
        assertThat(extensions.getAsJsonObject(), hasField("mfa-method"));
    }

    @Test
    void populatesExtensionsFromAuditContextAndVarargs() {
        var context = AUDIT_CONTEXT.withMetadataItem(pair("mfa-method", "DEFAULT", false));

        auditService.submitAuditEvent(
                AUTH_TEST_EVENT_ONE, context, pair("additional-extension", "value", false));

        verify(awsSqsClient).send(txmaMessageCaptor.capture());

        var txmaMessage = asJson(txmaMessageCaptor.getValue());
        System.out.println("audit event: " + txmaMessage);

        var extensions = txmaMessage.getAsJsonObject().get("extensions");
        assertThat(extensions.getAsJsonObject(), hasField("mfa-method"));
        assertThat(extensions.getAsJsonObject(), hasField("additional-extension"));
    }

    private void assertThatTheRestrictedSectionDoesNotExist() {
        var txmaMessage = asJson(txmaMessageCaptor.getValue());
        var restricted = txmaMessage.getAsJsonObject().get("restricted");
        assertTrue(restricted.isJsonNull());
    }

    private void assertThatTheRestrictedSectionDoesNotContainADeviceInformationObject() {
        var txmaMessage = asJson(txmaMessageCaptor.getValue());
        var restricted = txmaMessage.getAsJsonObject().get("restricted");
        assertThat(restricted.getAsJsonObject(), not(hasField("device_information")));
    }

    private void assertThatTheDeviceInformationIsWrittenToTheRestrictedSection() {
        var txmaMessage = asJson(txmaMessageCaptor.getValue());
        var restricted = txmaMessage.getAsJsonObject().get("restricted").getAsJsonObject();
        var deviceInformation =
                restricted.getAsJsonObject().get("device_information").getAsJsonObject();
        assertThat(
                deviceInformation,
                hasFieldWithValue("encoded", equalTo(ENCODED_DEVICE_INFORMATION)));
    }

    private void assertThatTheRestrictedDataPairsAreWrittenToTheRestrictedSection() {
        var txmaMessage = asJson(txmaMessageCaptor.getValue());
        var restricted = txmaMessage.getAsJsonObject().get("restricted").getAsJsonObject();
        assertThat(restricted, hasFieldWithValue("restrictedKey1", equalTo("restrictedValue1")));
    }

    @Test
    void shouldCombineMetadataFromContextAndVarargs() {
        // Given
        var context =
                AUDIT_CONTEXT
                        .withMetadataItem(pair("context-key", "context-value", false))
                        .withMetadataItem(
                                pair("context-restricted-key", "context-restricted-value", true));

        // When
        auditService.submitAuditEvent(
                AUTH_TEST_EVENT_ONE, context,
                pair("vararg-key", "vararg-value", false), pair("vararg-restricted-key", "vararg-restricted-value", true));

        // Then
        verify(awsSqsClient).send(txmaMessageCaptor.capture());
        var txmaMessage = asJson(txmaMessageCaptor.getValue());

        var extensions = txmaMessage.getAsJsonObject().get("extensions").getAsJsonObject();
        assertThat(extensions, hasFieldWithValue("context-key", equalTo("context-value")));
        assertThat(extensions, hasFieldWithValue("vararg-key", equalTo("vararg-value")));

        var restricted = txmaMessage.getAsJsonObject().get("restricted").getAsJsonObject();
assertThat(
                restricted,
                hasFieldWithValue("context-restricted-key", equalTo("context-restricted-value")));
        assertThat(
                restricted,
                hasFieldWithValue("vararg-restricted-key", equalTo("vararg-restricted-value")));
    }
}

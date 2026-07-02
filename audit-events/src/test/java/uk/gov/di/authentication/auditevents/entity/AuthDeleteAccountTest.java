package uk.gov.di.authentication.auditevents.entity;

import org.junit.jupiter.api.Test;
import uk.gov.di.audit.AuditContext;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.authentication.sharedtest.matchers.JsonMatcher.asJson;

class AuthDeleteAccountTest {

    private static final Instant FIXED_INSTANT = Instant.parse("2026-06-02T09:10:11.123Z");
    private static final Clock FIXED_CLOCK = Clock.fixed(FIXED_INSTANT, ZoneOffset.UTC);

    @Test
    void shouldSerializeWithAllFieldsIncludingLegacySubjectId() {
        var auditContext =
                AuditContext.emptyAuditContext()
                        .withClientId("client_id")
                        .withClientSessionId("govuk_signin_journey_id")
                        .withSessionId("session_id")
                        .withSubjectId("urn:fdc:gov.uk:2022:user_id")
                        .withEmail("email")
                        .withIpAddress("0.0.0.0")
                        .withPhoneNumber("+447234567890")
                        .withPersistentSessionId("persistent_session_id")
                        .withTxmaAuditEncoded("encoded_data");

        var event =
                AuthDeleteAccount.create(
                        auditContext,
                        "urn:fdc:gov.uk:2022:public_subject_id",
                        "urn:fdc:gov.uk:2022:legacy_subject_id",
                        "USER_INITIATED",
                        FIXED_CLOCK);

        var actualEvent = event.serialize();

        var expectedEvent =
                """
                {
                  "event_name": "AUTH_DELETE_ACCOUNT",
                  "timestamp": 1780391411,
                  "event_timestamp_ms": 1780391411123,
                  "client_id": "client_id",
                  "component_id": "AUTH",
                  "user": {
                    "email": "email",
                    "govuk_signin_journey_id": "govuk_signin_journey_id",
                    "ip_address": "0.0.0.0",
                    "legacy_subject_id": "urn:fdc:gov.uk:2022:legacy_subject_id",
                    "persistent_session_id": "persistent_session_id",
                    "phone": "+447234567890",
                    "public_subject_id": "urn:fdc:gov.uk:2022:public_subject_id",
                    "session_id": "session_id",
                    "user_id": "urn:fdc:gov.uk:2022:user_id"
                  },
                  "restricted": {
                    "device_information": {
                      "encoded": "encoded_data"
                    }
                  },
                  "extensions": {
                    "account_deletion_reason": "USER_INITIATED",
                    "phone_number_country_code": "44"
                  }
                }
                """;

        assertEquals(asJson(expectedEvent), asJson(actualEvent));
    }

    @Test
    void shouldOmitLegacySubjectIdWhenNull() {
        var auditContext =
                AuditContext.emptyAuditContext()
                        .withClientId("client_id")
                        .withClientSessionId("govuk_signin_journey_id")
                        .withSessionId("session_id")
                        .withSubjectId("urn:fdc:gov.uk:2022:user_id")
                        .withEmail("email")
                        .withIpAddress("0.0.0.0")
                        .withPhoneNumber("+447234567890")
                        .withPersistentSessionId("persistent_session_id")
                        .withTxmaAuditEncoded("encoded_data");

        var event =
                AuthDeleteAccount.create(
                        auditContext,
                        "urn:fdc:gov.uk:2022:public_subject_id",
                        null,
                        "USER_INITIATED",
                        FIXED_CLOCK);

        var actualEvent = event.serialize();

        var expectedEvent =
                """
                {
                  "event_name": "AUTH_DELETE_ACCOUNT",
                  "timestamp": 1780391411,
                  "event_timestamp_ms": 1780391411123,
                  "client_id": "client_id",
                  "component_id": "AUTH",
                  "user": {
                    "email": "email",
                    "govuk_signin_journey_id": "govuk_signin_journey_id",
                    "ip_address": "0.0.0.0",
                    "persistent_session_id": "persistent_session_id",
                    "phone": "+447234567890",
                    "public_subject_id": "urn:fdc:gov.uk:2022:public_subject_id",
                    "session_id": "session_id",
                    "user_id": "urn:fdc:gov.uk:2022:user_id"
                  },
                  "restricted": {
                    "device_information": {
                      "encoded": "encoded_data"
                    }
                  },
                  "extensions": {
                    "account_deletion_reason": "USER_INITIATED",
                    "phone_number_country_code": "44"
                  }
                }
                """;

        assertEquals(asJson(expectedEvent), asJson(actualEvent));
    }

    @Test
    void shouldOmitPhoneNumberCountryCodeWhenPhoneIsBlank() {
        var auditContext =
                AuditContext.emptyAuditContext()
                        .withClientId("client_id")
                        .withClientSessionId("govuk_signin_journey_id")
                        .withSessionId("session_id")
                        .withSubjectId("urn:fdc:gov.uk:2022:user_id")
                        .withEmail("email")
                        .withIpAddress("0.0.0.0")
                        .withPhoneNumber("")
                        .withPersistentSessionId("persistent_session_id")
                        .withTxmaAuditEncoded("encoded_data");

        var event =
                AuthDeleteAccount.create(
                        auditContext,
                        "urn:fdc:gov.uk:2022:public_subject_id",
                        null,
                        "USER_INITIATED",
                        FIXED_CLOCK);

        var actualEvent = event.serialize();

        var expectedEvent =
                """
                {
                  "event_name": "AUTH_DELETE_ACCOUNT",
                  "timestamp": 1780391411,
                  "event_timestamp_ms": 1780391411123,
                  "client_id": "client_id",
                  "component_id": "AUTH",
                  "user": {
                    "email": "email",
                    "govuk_signin_journey_id": "govuk_signin_journey_id",
                    "ip_address": "0.0.0.0",
                    "persistent_session_id": "persistent_session_id",
                    "phone": "",
                    "public_subject_id": "urn:fdc:gov.uk:2022:public_subject_id",
                    "session_id": "session_id",
                    "user_id": "urn:fdc:gov.uk:2022:user_id"
                  },
                  "restricted": {
                    "device_information": {
                      "encoded": "encoded_data"
                    }
                  },
                  "extensions": {
                    "account_deletion_reason": "USER_INITIATED"
                  }
                }
                """;

        assertEquals(asJson(expectedEvent), asJson(actualEvent));
    }

    @Test
    void shouldIncludePhoneNumberCountryCodeWhenPhoneIsValid() {
        var auditContext =
                AuditContext.emptyAuditContext()
                        .withClientId("client_id")
                        .withClientSessionId("govuk_signin_journey_id")
                        .withSessionId("session_id")
                        .withSubjectId("urn:fdc:gov.uk:2022:user_id")
                        .withEmail("email")
                        .withIpAddress("0.0.0.0")
                        .withPhoneNumber("+447234567890")
                        .withPersistentSessionId("persistent_session_id")
                        .withTxmaAuditEncoded("encoded_data");

        var event =
                AuthDeleteAccount.create(
                        auditContext,
                        "urn:fdc:gov.uk:2022:public_subject_id",
                        null,
                        "SECURITY_INITIATED",
                        FIXED_CLOCK);

        var actualEvent = event.serialize();

        var expectedEvent =
                """
                {
                  "event_name": "AUTH_DELETE_ACCOUNT",
                  "timestamp": 1780391411,
                  "event_timestamp_ms": 1780391411123,
                  "client_id": "client_id",
                  "component_id": "AUTH",
                  "user": {
                    "email": "email",
                    "govuk_signin_journey_id": "govuk_signin_journey_id",
                    "ip_address": "0.0.0.0",
                    "persistent_session_id": "persistent_session_id",
                    "phone": "+447234567890",
                    "public_subject_id": "urn:fdc:gov.uk:2022:public_subject_id",
                    "session_id": "session_id",
                    "user_id": "urn:fdc:gov.uk:2022:user_id"
                  },
                  "restricted": {
                    "device_information": {
                      "encoded": "encoded_data"
                    }
                  },
                  "extensions": {
                    "account_deletion_reason": "SECURITY_INITIATED",
                    "phone_number_country_code": "44"
                  }
                }
                """;

        assertEquals(asJson(expectedEvent), asJson(actualEvent));
    }
}

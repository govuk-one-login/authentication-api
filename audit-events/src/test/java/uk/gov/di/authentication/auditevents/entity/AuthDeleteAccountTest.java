package uk.gov.di.authentication.auditevents.entity;

import com.google.gson.JsonParser;
import org.junit.jupiter.api.Test;
import uk.gov.di.audit.AuditContext;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

class AuthDeleteAccountTest {

    private static final Clock FIXED_CLOCK =
            Clock.fixed(Instant.ofEpochMilli(1722953808667L), ZoneId.of("UTC"));

    private AuditContext auditContext(String phone) {
        return new AuditContext(
                "client_id",
                "govuk_signin_journey_id",
                "session_id",
                "urn:fdc:gov.uk:2022:user_id",
                "email",
                "0.0.0.0",
                phone,
                "persistent_session_id",
                "encoded_data");
    }

    @Test
    void shouldSerializeWithAllFieldsIncludingLegacySubjectId() {
        var event =
                AuthDeleteAccount.create(
                        auditContext("+447234567890"),
                        "urn:fdc:gov.uk:2022:public_subject_id",
                        "urn:fdc:gov.uk:2022:legacy_subject_id",
                        "USER_INITIATED",
                        FIXED_CLOCK);

        var json = JsonParser.parseString(event.serialize()).getAsJsonObject();

        assertEquals("AUTH_DELETE_ACCOUNT", json.get("event_name").getAsString());
        assertEquals(1722953808L, json.get("timestamp").getAsLong());
        assertEquals(1722953808667L, json.get("event_timestamp_ms").getAsLong());
        assertEquals("client_id", json.get("client_id").getAsString());
        assertEquals("AUTH", json.get("component_id").getAsString());

        var user = json.getAsJsonObject("user");
        assertEquals("email", user.get("email").getAsString());
        assertEquals("govuk_signin_journey_id", user.get("govuk_signin_journey_id").getAsString());
        assertEquals("0.0.0.0", user.get("ip_address").getAsString());
        assertEquals(
                "urn:fdc:gov.uk:2022:legacy_subject_id",
                user.get("legacy_subject_id").getAsString());
        assertEquals("persistent_session_id", user.get("persistent_session_id").getAsString());
        assertEquals("+447234567890", user.get("phone").getAsString());
        assertEquals(
                "urn:fdc:gov.uk:2022:public_subject_id",
                user.get("public_subject_id").getAsString());
        assertEquals("session_id", user.get("session_id").getAsString());
        assertEquals("urn:fdc:gov.uk:2022:user_id", user.get("user_id").getAsString());

        var restricted = json.getAsJsonObject("restricted");
        assertEquals(
                "encoded_data",
                restricted.getAsJsonObject("device_information").get("encoded").getAsString());

        var extensions = json.getAsJsonObject("extensions");
        assertEquals("USER_INITIATED", extensions.get("account_deletion_reason").getAsString());
        assertEquals("44", extensions.get("phone_number_country_code").getAsString());
    }

    @Test
    void shouldOmitLegacySubjectIdWhenNull() {
        var event =
                AuthDeleteAccount.create(
                        auditContext("+447234567890"),
                        "urn:fdc:gov.uk:2022:public_subject_id",
                        null,
                        "USER_INITIATED",
                        FIXED_CLOCK);

        var json = JsonParser.parseString(event.serialize()).getAsJsonObject();
        var user = json.getAsJsonObject("user");

        assertFalse(user.has("legacy_subject_id"));
        assertEquals(
                "urn:fdc:gov.uk:2022:public_subject_id",
                user.get("public_subject_id").getAsString());
    }

    @Test
    void shouldOmitPhoneNumberCountryCodeWhenPhoneIsBlank() {
        var event =
                AuthDeleteAccount.create(
                        auditContext(""),
                        "urn:fdc:gov.uk:2022:public_subject_id",
                        null,
                        "USER_INITIATED",
                        FIXED_CLOCK);

        var json = JsonParser.parseString(event.serialize()).getAsJsonObject();
        var extensions = json.getAsJsonObject("extensions");

        assertFalse(extensions.has("phone_number_country_code"));
        assertEquals("USER_INITIATED", extensions.get("account_deletion_reason").getAsString());
    }

    @Test
    void shouldIncludePhoneNumberCountryCodeWhenPhoneIsValid() {
        var event =
                AuthDeleteAccount.create(
                        auditContext("+447234567890"),
                        "urn:fdc:gov.uk:2022:public_subject_id",
                        null,
                        "SECURITY_INITIATED",
                        FIXED_CLOCK);

        var json = JsonParser.parseString(event.serialize()).getAsJsonObject();
        var extensions = json.getAsJsonObject("extensions");

        assertEquals("44", extensions.get("phone_number_country_code").getAsString());
    }
}

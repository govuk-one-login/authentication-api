package uk.gov.di.accountmanagement.entity;

import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.SerializationService;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class InactiveAccountDeletionMessageTest {

    private final Json objectMapper = SerializationService.getInstance();

    @Test
    void shouldDeserializeValidMessage() throws Json.JsonException {
        String json = "{\"publicSubjectId\": \"urn:fdc:gov.uk:2022:abc123\"}";

        var message = objectMapper.readValue(json, InactiveAccountDeletionMessage.class);

        assertEquals("urn:fdc:gov.uk:2022:abc123", message.publicSubjectId());
    }

    @Test
    void shouldDeserializeMessageWithNullPublicSubjectId() throws Json.JsonException {
        String json = "{}";

        var message = objectMapper.readValue(json, InactiveAccountDeletionMessage.class);

        assertNull(message.publicSubjectId());
    }

    @Test
    void shouldIgnoreUnknownFields() throws Json.JsonException {
        String json = "{\"publicSubjectId\": \"sub-123\", \"extraField\": \"should-be-ignored\"}";

        var message = objectMapper.readValue(json, InactiveAccountDeletionMessage.class);

        assertEquals("sub-123", message.publicSubjectId());
    }
}

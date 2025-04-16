package uk.gov.di.authentication.entity;

import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.NotifyRequest;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.SerializationService;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class NotifyRequestTest {
    private final Json objectMapper = SerializationService.getInstance();

    @Test
    void shouldUseUniqueNotificationReferenceIfProvided() throws Json.JsonException {
        var requestJson =
                """
                {
                    "notificationType": "VERIFY_EMAIL",
                    "destination": "test@example.com",
                    "unique_notification_reference": "testUniqueNotificationReference"
                }
                """;

        var notifyRequest = objectMapper.readValue(requestJson, NotifyRequest.class);

        assertEquals(
                "testUniqueNotificationReference", notifyRequest.getUniqueNotificationReference());
    }

    @Test
    void shouldGenerateUniqueNotificationReferenceIfNoneProvided() throws Json.JsonException {
        var requestJson =
                """
                {
                    "notificationType": "VERIFY_EMAIL",
                    "destination": "test@example.com"
                }
                """;

        var notifyRequest = objectMapper.readValue(requestJson, NotifyRequest.class);

        assertNotNull(notifyRequest.getUniqueNotificationReference());
        assertDoesNotThrow(() -> UUID.fromString(notifyRequest.getUniqueNotificationReference()));
    }
}

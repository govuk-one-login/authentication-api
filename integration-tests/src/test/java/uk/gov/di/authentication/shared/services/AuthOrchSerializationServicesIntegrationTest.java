package uk.gov.di.authentication.shared.services;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.internal.matchers.apachecommons.ReflectionEquals;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.serialization.Json;

import static org.mockito.Mockito.mock;

class AuthOrchSerializationServicesIntegrationTest {
    private final ConfigurationService configuration = mock(ConfigurationService.class);
    private final Json authObjectMapper = SerializationService.getInstance();
    private final uk.gov.di.orchestration.shared.serialization.Json OrchobjectMapper =
            uk.gov.di.orchestration.shared.services.SerializationService.getInstance();

    @Test
    void sessionsSerializedByAuthCanBeDeserializedByOrch()
            throws Json.JsonException,
                    uk.gov.di.orchestration.shared.serialization.Json.JsonException {
        var authSession =
                new Session("session-id")
                        .withBrowserSessionId("browser-session-id")
                        .addClientSession("client-session-id");
        var orchSession =
                new uk.gov.di.orchestration.shared.entity.Session("session-id")
                        .withBrowserSessionId("browser-session-id")
                        .addClientSession("client-session-id");

        var authSerializedSession = authObjectMapper.writeValueAsString(authSession);
        var orchDeserialized =
                OrchobjectMapper.readValue(
                        authSerializedSession, uk.gov.di.orchestration.shared.entity.Session.class);

        Assertions.assertTrue(new ReflectionEquals(orchSession).matches(orchDeserialized));
    }
}

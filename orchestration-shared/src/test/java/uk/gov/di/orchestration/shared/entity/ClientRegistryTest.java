package uk.gov.di.orchestration.shared.entity;

import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.Mockito.mock;

class ClientRegistryTest {

    private final ClientRegistry clientRegistry = mock(ClientRegistry.class);

    @Test
    void shouldReturnDefaultLoCsWhenRegistryEmpty() {
        var clientRegistry = new ClientRegistry();
        assertThat(
                clientRegistry.getClientLoCs(),
                equalTo(LevelOfConfidence.getDefaultLevelOfConfidenceValues()));
    }
}

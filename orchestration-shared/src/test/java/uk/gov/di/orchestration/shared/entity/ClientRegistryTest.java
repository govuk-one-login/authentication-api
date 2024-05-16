package uk.gov.di.orchestration.shared.entity;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.Mockito.mock;

class ClientRegistryTest {

    private final ClientRegistry clientRegistry = mock(ClientRegistry.class);

    @Test
    void shouldReturnP2andP0WhenidentityVerificationSupportedAndRegistryEmpty() {
        var clientRegistry = new ClientRegistry();
        clientRegistry.setIdentityVerificationSupported(true);
        assertThat(
                clientRegistry.getClientLoCs(),
                equalTo(
                        List.of(
                                LevelOfConfidence.MEDIUM_LEVEL.getValue(),
                                LevelOfConfidence.NONE.getValue())));
    }

    @Test
    void shouldReturnP0WhenidentityVerificationNotSupportedAndRegistryEmpty() {
        var clientRegistry = new ClientRegistry();
        clientRegistry.setIdentityVerificationSupported(false);
        assertThat(
                clientRegistry.getClientLoCs(),
                equalTo(List.of(LevelOfConfidence.NONE.getValue())));
    }
}

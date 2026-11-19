package uk.gov.di.authentication.shared.helpers;

import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class Argon2HashParametersTest {

    private final ConfigurationService configurationService = mock(ConfigurationService.class);

    @Test
    void shouldBuildFromConfigurationWithArgon2idAndVersion19() {
        setupConfig(32768, 3, 4);

        var params = Argon2HashParameters.fromConfiguration(configurationService);

        assertEquals(new Argon2HashParameters("argon2id", 19, 32768, 3, 4), params);
    }

    private void setupConfig(int memory, int iterations, int parallelism) {
        when(configurationService.getArgon2MemoryInKibibytes()).thenReturn(memory);
        when(configurationService.getArgon2Iterations()).thenReturn(iterations);
        when(configurationService.getArgon2Parallelism()).thenReturn(parallelism);
    }
}

package uk.gov.di.authentication.ipv.services;

import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class IPVCapacityServiceTest {

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final IPVCapacityService ipvCapacityService =
            new IPVCapacityService(configurationService);

    @Test
    void shouldReturnTrueWhenCapacityAvailableFlagIs1() {
        when(configurationService.getIPVCapacity()).thenReturn(Optional.of("1"));
        assertThat(ipvCapacityService.isIPVCapacityAvailable(), equalTo(true));
    }

    @Test
    void shouldReturnTrueWhenCapacityAvailableFlagIsNot1() {
        when(configurationService.getIPVCapacity()).thenReturn(Optional.of("hello"));
        assertThat(ipvCapacityService.isIPVCapacityAvailable(), equalTo(false));
    }

    @Test
    void shouldReturnFalseWhenCapacityAvailableFlagIsUnset() {
        when(configurationService.getIPVCapacity()).thenReturn(Optional.empty());
        assertThat(ipvCapacityService.isIPVCapacityAvailable(), equalTo(false));
    }
}

package uk.gov.di.authentication.shared.state.conditions;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ConsentIsNotRequiredTest {

    private final ConsentIsNotRequired condition = new ConsentIsNotRequired();
    private UserContext userContext = mock(UserContext.class);
    private ClientRegistry client = mock(ClientRegistry.class);

    @BeforeEach
    void setup() {
        when(userContext.getClient()).thenReturn(Optional.of(client));
    }

    @Test
    void shouldReturnTrueIfConsentIsNotRequired() {
        when(client.isConsentRequired()).thenReturn(false);

        assertThat(condition.isMet(Optional.of(userContext)), equalTo(true));
    }

    @Test
    void shouldReturnFalseIfConsentIsRequired() {
        when(client.isConsentRequired()).thenReturn(true);

        assertThat(condition.isMet(Optional.of(userContext)), equalTo(false));
    }

    @Test
    void shouldDefaultToTrueIfClientHasNotSpecifiedWhetherConsentIsRequired() {
        assertThat(condition.isMet(Optional.of(userContext)), equalTo(true));
    }
}

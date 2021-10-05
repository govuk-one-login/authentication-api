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

class ClientIsAnInternalServiceTest {

    private final ClientIsAnInternalService condition = new ClientIsAnInternalService();
    private UserContext userContext = mock(UserContext.class);
    private ClientRegistry client = mock(ClientRegistry.class);

    @BeforeEach
    public void setup() {
        when(userContext.getClient()).thenReturn(Optional.of(client));
    }

    @Test
    public void shouldReturnTrueIfClientIsAnInternalService() {
        when(client.isInternalService()).thenReturn(true);

        assertThat(condition.isMet(Optional.of(userContext)), equalTo(true));
    }

    @Test
    public void shouldReturnFalseIfClientIsNotAnInternalService() {
        when(client.isInternalService()).thenReturn(false);

        assertThat(condition.isMet(Optional.of(userContext)), equalTo(false));
    }

    @Test
    public void shouldReturnFalseIfClientHasNotSpecifiedWhetherTheyAreAnInternalService() {
        assertThat(condition.isMet(Optional.of(userContext)), equalTo(false));
    }
}

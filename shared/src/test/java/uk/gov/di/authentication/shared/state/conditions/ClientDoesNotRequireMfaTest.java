package uk.gov.di.authentication.shared.state.conditions;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.entity.CredentialTrustLevel.LOW_LEVEL;
import static uk.gov.di.authentication.shared.entity.CredentialTrustLevel.MEDIUM_LEVEL;

class ClientDoesNotRequireMfaTest {
    private final ClientDoesNotRequireMfa condition = new ClientDoesNotRequireMfa();
    private UserContext userContext = mock(UserContext.class);
    private ClientRegistry client = mock(ClientRegistry.class);
    private VectorOfTrust vectorOfTrust = mock(VectorOfTrust.class);

    @BeforeEach
    public void setup() {
        when(userContext.getClient()).thenReturn(Optional.of(client));
        when(client.calculateEffectiveVectorOfTrust()).thenReturn(vectorOfTrust);
    }

    @Test
    public void shouldReturnTrueIfLowLevelOfTrust() {
        when(vectorOfTrust.getCredentialTrustLevel()).thenReturn(LOW_LEVEL);

        assertThat(condition.isMet(Optional.of(userContext)), equalTo(true));
    }

    @Test
    public void shouldReturnFalseIfNotLowLevelOfTrust() {
        when(vectorOfTrust.getCredentialTrustLevel()).thenReturn(MEDIUM_LEVEL);

        assertThat(condition.isMet(Optional.of(userContext)), equalTo(false));
    }

    @Test
    public void shouldReturnFalseIfClientDoesNotExistInContext() {
        when(userContext.getClient()).thenReturn(Optional.empty());

        assertThat(condition.isMet(Optional.of(userContext)), equalTo(false));
    }
}

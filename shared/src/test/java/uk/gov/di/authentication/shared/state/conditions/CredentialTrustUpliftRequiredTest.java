package uk.gov.di.authentication.shared.state.conditions;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.entity.CredentialTrustLevel.LOW_LEVEL;
import static uk.gov.di.authentication.shared.entity.CredentialTrustLevel.MEDIUM_LEVEL;

public class CredentialTrustUpliftRequiredTest {

    private final UserContext userContext = mock(UserContext.class);
    private final Session session = mock(Session.class);
    private final ClientSession clientSession = mock(ClientSession.class);
    private final VectorOfTrust vectorOfTrust = mock(VectorOfTrust.class);

    @BeforeEach
    public void setup() {
        when(userContext.getSession()).thenReturn(session);
        when(userContext.getClientSession()).thenReturn(clientSession);
        when(clientSession.getEffectiveVectorOfTrust()).thenReturn(vectorOfTrust);
    }

    @Test
    public void shouldReturnTrueIfUpliftRequired() {
        CredentialTrustUpliftRequired condition = new CredentialTrustUpliftRequired();
        when(session.getCurrentCredentialStrength()).thenReturn(LOW_LEVEL);
        when(vectorOfTrust.getCredentialTrustLevel()).thenReturn(MEDIUM_LEVEL);

        assertThat(condition.isMet(Optional.of(userContext)), equalTo(true));
    }

    @Test
    public void shouldReturnFalseIfSessionAlreadyAtRequiredLevelOfTrust() {
        CredentialTrustUpliftRequired condition = new CredentialTrustUpliftRequired();
        when(session.getCurrentCredentialStrength()).thenReturn(MEDIUM_LEVEL);
        when(vectorOfTrust.getCredentialTrustLevel()).thenReturn(MEDIUM_LEVEL);

        assertThat(condition.isMet(Optional.of(userContext)), equalTo(false));
    }

    @Test
    public void shouldReturnFalseIfSessionAlreadyAtHigherLevelOfTrust() {
        CredentialTrustUpliftRequired condition = new CredentialTrustUpliftRequired();
        when(session.getCurrentCredentialStrength()).thenReturn(MEDIUM_LEVEL);
        when(vectorOfTrust.getCredentialTrustLevel()).thenReturn(LOW_LEVEL);

        assertThat(condition.isMet(Optional.of(userContext)), equalTo(false));
    }

    @Test
    public void shouldReturnFalseIfSessionHasNotRecordedACredentialTrustLevel() {
        CredentialTrustUpliftRequired condition = new CredentialTrustUpliftRequired();
        when(session.getCurrentCredentialStrength()).thenReturn(null);
        when(vectorOfTrust.getCredentialTrustLevel()).thenReturn(null);

        assertThat(condition.isMet(Optional.of(userContext)), equalTo(false));
    }
}

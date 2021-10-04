package uk.gov.di.authentication.shared.state.conditions;

import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.shared.state.UserContext;

import java.net.URI;
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
    private ClientSession clientSession = mock(ClientSession.class);
    private VectorOfTrust vectorOfTrust = mock(VectorOfTrust.class);

    @BeforeEach
    public void setup() {
        when(userContext.getClient()).thenReturn(Optional.of(client));
        when(userContext.getClientSession()).thenReturn(clientSession);
    }

    @Test
    public void shouldReturnTrueIfLowLevelOfTrust() {
        when(clientSession.getAuthRequestParams())
                .thenReturn(generateAuthRequest(Optional.of("Cl")).toParameters());
        when(vectorOfTrust.getCredentialTrustLevel()).thenReturn(LOW_LEVEL);

        assertThat(condition.isMet(Optional.of(userContext)), equalTo(true));
    }

    @Test
    public void shouldReturnFalseIfNotLowLevelOfTrust() {
        when(clientSession.getAuthRequestParams())
                .thenReturn(generateAuthRequest(Optional.of("Cl.Cm")).toParameters());
        when(vectorOfTrust.getCredentialTrustLevel()).thenReturn(MEDIUM_LEVEL);

        assertThat(condition.isMet(Optional.of(userContext)), equalTo(false));
    }

    @Test
    public void shouldReturnFalseIfAuthRequestDoesNotContainVtr() {
        when(clientSession.getAuthRequestParams())
                .thenReturn(generateAuthRequest(Optional.empty()).toParameters());

        when(userContext.getClient()).thenReturn(Optional.empty());

        assertThat(condition.isMet(Optional.of(userContext)), equalTo(false));
    }

    private AuthenticationRequest generateAuthRequest(Optional<String> credentialTrustLevel) {
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        AuthenticationRequest.Builder builder =
                new AuthenticationRequest.Builder(
                                ResponseType.CODE,
                                scope,
                                new ClientID(),
                                URI.create("http://localhost/redirect"))
                        .state(new State())
                        .nonce(new Nonce());

        credentialTrustLevel.ifPresent(t -> builder.customParameter("vtr", t));
        return builder.build();
    }
}

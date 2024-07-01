package uk.gov.di.orchestration.shared.entity;

import com.nimbusds.jose.JWSAlgorithm;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

class ClientRegistryTest {

    @Test
    void shouldReturnP2andP0WhenidentityVerificationSupportedAndRegistryEmpty() {
        var clientRegistry = new ClientRegistry();
        clientRegistry.setIdentityVerificationSupported(true);
        assertThat(
                clientRegistry.getClientLoCs(),
                equalTo(
                        List.of(
                                LevelOfConfidence.MEDIUM_LEVEL.toString(),
                                LevelOfConfidence.NONE.toString())));
    }

    @Test
    void shouldReturnP0WhenidentityVerificationNotSupportedAndRegistryEmpty() {
        var clientRegistry = new ClientRegistry();
        clientRegistry.setIdentityVerificationSupported(false);
        assertThat(
                clientRegistry.getClientLoCs(),
                equalTo(List.of(LevelOfConfidence.NONE.toString())));
    }

    @Test
    void shouldReturnES256IdTokenSigningAlgorithmCorrectly() {
        var clientRegistry = new ClientRegistry();
        clientRegistry.setIdTokenSigningAlgorithm(JWSAlgorithm.ES256.getName());
        assertThat(
                clientRegistry.getIdTokenSigningAlgorithm(), equalTo(JWSAlgorithm.ES256.getName()));
    }

    @Test
    void shouldReturnRS256IdTokenSigningAlgorithmCorrectly() {
        var clientRegistry = new ClientRegistry();
        clientRegistry.setIdTokenSigningAlgorithm(JWSAlgorithm.RS256.getName());
        assertThat(
                clientRegistry.getIdTokenSigningAlgorithm(), equalTo(JWSAlgorithm.RS256.getName()));
    }

    @Test
    void shouldReturnRS256IdTokenSigningAlgorithmWhenRSA256IsUsed() {
        var clientRegistry = new ClientRegistry();
        clientRegistry.setIdTokenSigningAlgorithm("RSA256");
        assertThat(
                clientRegistry.getIdTokenSigningAlgorithm(), equalTo(JWSAlgorithm.RS256.getName()));
    }

    @Test
    void shouldReturnNullIdTokenSigningAlgorithmCorrectly() {
        var clientRegistry = new ClientRegistry();
        clientRegistry.setIdTokenSigningAlgorithm(null);
        assertThat(clientRegistry.getIdTokenSigningAlgorithm(), equalTo(null));
    }
}

package uk.gov.di.orchestration.shared.entity;

import com.nimbusds.jose.JWSAlgorithm;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.List;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

// QualityGateUnitTest
class ClientRegistryTest {

    // QualityGateRegressionTest
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

    // QualityGateRegressionTest
    @Test
    void shouldReturnP0WhenidentityVerificationNotSupportedAndRegistryEmpty() {
        var clientRegistry = new ClientRegistry();
        clientRegistry.setIdentityVerificationSupported(false);
        assertThat(
                clientRegistry.getClientLoCs(),
                equalTo(List.of(LevelOfConfidence.NONE.getValue())));
    }

    // QualityGateRegressionTest
    @Test
    void shouldReturnES256IdTokenSigningAlgorithmCorrectly() {
        var clientRegistry = new ClientRegistry();
        clientRegistry.setIdTokenSigningAlgorithm(JWSAlgorithm.ES256.getName());
        assertThat(
                clientRegistry.getIdTokenSigningAlgorithm(), equalTo(JWSAlgorithm.ES256.getName()));
    }

    // QualityGateRegressionTest
    @Test
    void shouldReturnRS256IdTokenSigningAlgorithmCorrectly() {
        var clientRegistry = new ClientRegistry();
        clientRegistry.setIdTokenSigningAlgorithm(JWSAlgorithm.RS256.getName());
        assertThat(
                clientRegistry.getIdTokenSigningAlgorithm(), equalTo(JWSAlgorithm.RS256.getName()));
    }

    // QualityGateRegressionTest
    @Test
    void shouldReturnRS256IdTokenSigningAlgorithmWhenRSA256IsUsed() {
        var clientRegistry = new ClientRegistry();
        clientRegistry.setIdTokenSigningAlgorithm("RSA256");
        assertThat(
                clientRegistry.getIdTokenSigningAlgorithm(), equalTo(JWSAlgorithm.RS256.getName()));
    }

    // QualityGateRegressionTest
    @Test
    void shouldReturnNullIdTokenSigningAlgorithmCorrectly() {
        var clientRegistry = new ClientRegistry();
        clientRegistry.setIdTokenSigningAlgorithm(null);
        assertThat(clientRegistry.getIdTokenSigningAlgorithm(), equalTo(null));
    }

    /**
     * Old client registry entries will have a public key but no public key source in the DB.
     * getPublicKeySource should therefore return STATIC by default.
     */
    // QualityGateRegressionTest
    @Test
    void shouldReturnCorrectlyPublicKeyAndSourceForOldFormatClient() {
        var clientRegistry = new ClientRegistry();

        var actualKey = "example-key";
        clientRegistry.setPublicKey(actualKey);

        assertThat(clientRegistry.getPublicKey(), equalTo(actualKey));
        assertThat(clientRegistry.getPublicKeySource(), equalTo(PublicKeySource.STATIC.getValue()));
        assertThat(clientRegistry.getJwksUrl(), equalTo(null));
    }

    // QualityGateRegressionTest
    @Test
    void shouldReturnCorrectlyPublicKeyAndSourceForNewFormatClient() {
        var clientRegistry = new ClientRegistry();

        var actualKey = "example-key";
        clientRegistry.setPublicKey(actualKey);
        clientRegistry.setPublicKeySource(PublicKeySource.STATIC.getValue());

        assertThat(clientRegistry.getPublicKey(), equalTo(actualKey));
        assertThat(clientRegistry.getPublicKeySource(), equalTo(PublicKeySource.STATIC.getValue()));
        assertThat(clientRegistry.getJwksUrl(), equalTo(null));
    }

    // QualityGateRegressionTest
    @Test
    void shouldReturnCorrectlyJwksUrlAndSourceForNewFormatClient() {
        var clientRegistry = new ClientRegistry();

        var actualUrl = "example-url";
        clientRegistry.setJwksUrl(actualUrl);
        clientRegistry.setPublicKeySource(PublicKeySource.JWKS.getValue());

        assertThat(clientRegistry.getPublicKey(), equalTo(null));
        assertThat(clientRegistry.getPublicKeySource(), equalTo(PublicKeySource.JWKS.getValue()));
        assertThat(clientRegistry.getJwksUrl(), equalTo(actualUrl));
    }

    /**
     * When an existing client is updated with a JWKS URL, we should hide the existing public key in
     * the DB.
     */
    // QualityGateRegressionTest
    @Test
    void shouldReturnCorrectlyJwksUrlAndSourceForOldFormatThatGetUpdateWithAJwksUrlClient() {
        var clientRegistry = new ClientRegistry();

        var oldKey = "example-key";
        clientRegistry.setPublicKey(oldKey);
        clientRegistry.setPublicKeySource(PublicKeySource.STATIC.getValue());

        var actualUrl = "example-url";
        clientRegistry.setJwksUrl(actualUrl);
        clientRegistry.setPublicKeySource(PublicKeySource.JWKS.getValue());

        assertThat(clientRegistry.getPublicKey(), equalTo(null));
        assertThat(clientRegistry.getPublicKeySource(), equalTo(PublicKeySource.JWKS.getValue()));
        assertThat(clientRegistry.getJwksUrl(), equalTo(actualUrl));
    }

    private static Stream<Arguments> permutationsToCheck() {
        return Stream.of(
                Arguments.of(true, true),
                Arguments.of(true, false),
                Arguments.of(false, true),
                Arguments.of(false, false));
    }

    // QualityGateRegressionTest
    @ParameterizedTest
    @MethodSource("permutationsToCheck")
    void shouldOnlyReturnPermitMissingNonceTrueWhenIdentityVerificationSupportedIsAlsoFalse(
            boolean identityVerificationSupported, boolean permitMissingNonce) {
        var clientRegistry = new ClientRegistry();
        clientRegistry.setIdentityVerificationSupported(identityVerificationSupported);
        clientRegistry.setPermitMissingNonce(permitMissingNonce);
        if (identityVerificationSupported == false && permitMissingNonce == true) {
            assertThat(clientRegistry.permitMissingNonce(), equalTo(true));
        } else {
            assertThat(clientRegistry.permitMissingNonce(), equalTo(false));
        }
    }
}

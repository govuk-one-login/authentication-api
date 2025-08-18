package uk.gov.di.orchestration.shared.helpers;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.sharedtest.utils.KeyPairUtils;

import java.security.KeyPair;
import java.util.Base64;
import java.util.List;

import static com.nimbusds.openid.connect.sdk.SubjectType.PUBLIC;
import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ClientSubjectHelperTest {

    private static final String TEST_EMAIL = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String REDIRECT_URI = "http://localhost/redirect";
    private static final String INTERNAL_SECTOR_URI = "https://test.account.gov.uk";
    private static final Scope SCOPES =
            new Scope(OIDCScopeValue.OPENID, OIDCScopeValue.EMAIL, OIDCScopeValue.OFFLINE_ACCESS);
    private KeyPair keyPair;

    @BeforeEach
    void setUp() {
        keyPair = KeyPairUtils.generateRsaKeyPair();
    }

    @Test
    void shouldGetHostAsSectorIdentifierWhenDefinedByClient() {
        var clientRegistry =
                generateClientRegistryPairwise(
                        keyPair, "test-client-id-1", PUBLIC.toString(), "https://test.com", false);

        var sectorId =
                ClientSubjectHelper.getSectorIdentifierForClient(
                        clientRegistry, INTERNAL_SECTOR_URI);

        assertThat(sectorId, equalTo("test.com"));
    }

    @Test
    void shouldGetHostOfInternalSectorUriWhenClientIsOneLoginService() {
        var clientRegistry =
                generateClientRegistryPairwise(
                        keyPair, "test-client-id-1", PUBLIC.toString(), null, true);

        var sectorId =
                ClientSubjectHelper.getSectorIdentifierForClient(
                        clientRegistry, INTERNAL_SECTOR_URI);

        assertThat(sectorId, equalTo("test.account.gov.uk"));
    }

    @Test
    void shouldUseHostOfInternalSectorUriWhenOneLoginServiceAndClientHasRegisteredSector() {
        var clientRegistry =
                generateClientRegistryPairwise(
                        keyPair, "test-client-id-1", PUBLIC.toString(), "https://test.com", true);

        var sectorId =
                ClientSubjectHelper.getSectorIdentifierForClient(
                        clientRegistry, INTERNAL_SECTOR_URI);

        assertThat(sectorId, equalTo("test.account.gov.uk"));
    }

    @Test
    void shouldCalculateHostFromRedirectUriWhenSectorUriIsNotDefinedByClient() {
        var clientRegistry =
                generateClientRegistryPairwise(
                        keyPair, "test-client-id-1", PUBLIC.toString(), null, false);

        var sectorId =
                ClientSubjectHelper.getSectorIdentifierForClient(
                        clientRegistry, INTERNAL_SECTOR_URI);

        assertThat(sectorId, equalTo("localhost"));
    }

    @Test
    void shouldThrowExceptionWhenClientConfigSectorIdInvalid() {
        var clientRegistry =
                generateClientRegistryPairwise(
                        keyPair,
                        "test-client-id-1",
                        PUBLIC.toString(),
                        null,
                        List.of("https://www.test.com", "https://www.test2.com"),
                        false);

        assertThrows(
                RuntimeException.class,
                () ->
                        ClientSubjectHelper.getSectorIdentifierForClient(
                                clientRegistry, INTERNAL_SECTOR_URI),
                "Expected to throw exception");
    }

    @Test
    void shouldReturnHostForValidSectorUri() {
        assertThat(ClientSubjectHelper.returnHost("https://test.com/hello"), equalTo("test.com"));
    }

    @Test
    void shouldReturnHostForInternalSectorUri() {
        assertThat(
                ClientSubjectHelper.returnHost(INTERNAL_SECTOR_URI),
                equalTo("test.account.gov.uk"));
    }

    @Test
    void shouldReturnHostForValidSectorUriStartingWWW() {
        assertThat(
                ClientSubjectHelper.returnHost("https://www.test.com/hello"), equalTo("test.com"));
    }

    @Test
    void shouldThrowExceptionWhenReturnHostIsNotAValidUri() {
        var expectedException =
                assertThrows(
                        RuntimeException.class,
                        () -> ClientSubjectHelper.returnHost("www.test.com/hello"),
                        "Expected to throw exception");
        assertEquals(NullPointerException.class, expectedException.getCause().getClass());
    }

    @Test
    void shouldThrowExceptionWhenReturnHostIsNotAWellFormedUri() {
        var expectedException =
                assertThrows(
                        RuntimeException.class,
                        () -> ClientSubjectHelper.returnHost("https://test..com"),
                        "Expected to throw exception");
        assertEquals(NullPointerException.class, expectedException.getCause().getClass());
    }

    @Test
    void shouldThrowExceptionWhenReturnHostIsNotAWellFormedUriWithoutHttps() {
        var expectedException =
                assertThrows(
                        RuntimeException.class,
                        () -> ClientSubjectHelper.returnHost("test..com"),
                        "Expected to throw exception");
        assertEquals(NullPointerException.class, expectedException.getCause().getClass());
    }

    @Test
    void shouldBeValidClientWithoutSectorId() {
        var clientRegistry =
                generateClientRegistryPairwise(
                        keyPair, "test-client-id-1", PUBLIC.toString(), null, false);

        assertTrue(ClientSubjectHelper.hasValidClientConfig(clientRegistry));
    }

    @Test
    void shouldBeValidClientWithSectorId() {
        var clientRegistry =
                generateClientRegistryPairwise(
                        keyPair, "test-client-id-1", PUBLIC.toString(), "https://test.com", false);

        assertTrue(ClientSubjectHelper.hasValidClientConfig(clientRegistry));
    }

    @Test
    void shouldBeValidClientWithSectorIdAndTwoRedirectHosts() {
        var clientRegistry =
                generateClientRegistryPairwise(
                        keyPair,
                        "test-client-id-1",
                        PUBLIC.toString(),
                        "https://test.com",
                        List.of("https://www.test.com", "https://www.test2.com"),
                        false);

        assertTrue(ClientSubjectHelper.hasValidClientConfig(clientRegistry));
    }

    @Test
    void shouldBeInvalidClientWithoutSectorIdAndTwoRedirectHosts() {
        var clientRegistry =
                generateClientRegistryPairwise(
                        keyPair,
                        "test-client-id-1",
                        PUBLIC.toString(),
                        null,
                        List.of("https://www.test.com", "https://www.test2.com"),
                        false);

        assertFalse(ClientSubjectHelper.hasValidClientConfig(clientRegistry));
    }

    @Test
    void shouldBeValidClientWithoutSectorIdAndOneRedirectHostsWithTwoRedirectUris() {
        var clientRegistry =
                generateClientRegistryPairwise(
                        keyPair,
                        "test-client-id-1",
                        PUBLIC.toString(),
                        null,
                        List.of("https://www.test.com/1", "https://www.test.com/2"),
                        false);

        assertTrue(ClientSubjectHelper.hasValidClientConfig(clientRegistry));
    }

    private ClientRegistry generateClientRegistryPairwise(
            KeyPair keyPair,
            String clientID,
            String subjectType,
            String sector,
            boolean oneLoginService) {
        return generateClientRegistryPairwise(
                keyPair,
                clientID,
                subjectType,
                sector,
                singletonList(REDIRECT_URI),
                oneLoginService);
    }

    private ClientRegistry generateClientRegistryPairwise(
            KeyPair keyPair,
            String clientID,
            String subjectType,
            String sector,
            List<String> redirectUrls,
            boolean oneLoginService) {
        return new ClientRegistry()
                .withClientID(clientID)
                .withClientName("test-client")
                .withRedirectUrls(redirectUrls)
                .withScopes(SCOPES.toStringList())
                .withContacts(singletonList(TEST_EMAIL))
                .withPublicKey(
                        Base64.getMimeEncoder().encodeToString(keyPair.getPublic().getEncoded()))
                .withSectorIdentifierUri(sector)
                .withOneLoginService(oneLoginService)
                .withSubjectType(subjectType);
    }
}

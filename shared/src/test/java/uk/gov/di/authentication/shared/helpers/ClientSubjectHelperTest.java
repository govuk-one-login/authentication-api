package uk.gov.di.authentication.shared.helpers;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.ClientConsent;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.ValidScopes;
import uk.gov.di.authentication.shared.services.AuthenticationService;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Base64;
import java.util.List;
import java.util.Set;

import static java.util.Collections.singletonList;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ClientSubjectHelperTest {

    private static final String TEST_EMAIL = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String PHONE_NUMBER = "01234567890";
    private static final String REDIRECT_URI = "http://localhost/redirect";
    private static final Subject INTERNAL_SUBJECT = new Subject();
    private static final Subject PUBLIC_SUBJECT = new Subject();
    private static final String CLIENT_ID = "test-id";
    private static final Scope SCOPES =
            new Scope(OIDCScopeValue.OPENID, OIDCScopeValue.EMAIL, OIDCScopeValue.OFFLINE_ACCESS);

    private final AuthenticationService authenticationService = mock(AuthenticationService.class);

    @Test
    void shouldReturnDifferentSubjectIDForMultipleClientsWithDifferentSectors() {
        stubAuthenticationService();
        KeyPair keyPair = generateRsaKeyPair();
        UserProfile userProfile = generateUserProfile();

        ClientRegistry clientRegistry1 =
                generateClientRegistryPairwise(
                        keyPair, "test-client-id-1", "pairwise", "https://test.com");
        ClientRegistry clientRegistry2 =
                generateClientRegistryPairwise(
                        keyPair, "test-client-id-2", "pairwise", "https://not-test.com");

        Subject subject1 =
                ClientSubjectHelper.getSubject(userProfile, clientRegistry1, authenticationService);
        Subject subject2 =
                ClientSubjectHelper.getSubject(userProfile, clientRegistry2, authenticationService);

        assertNotEquals(subject1, subject2);
    }

    @Test
    void shouldReturnSameSubjectIDForMultipleClientsWithSameSector() {
        stubAuthenticationService();
        KeyPair keyPair = generateRsaKeyPair();
        UserProfile userProfile = generateUserProfile();

        ClientRegistry clientRegistry1 =
                generateClientRegistryPairwise(
                        keyPair, "test-client-id-1", "pairwise", "https://test.com");
        ClientRegistry clientRegistry2 =
                generateClientRegistryPairwise(
                        keyPair, "test-client-id-2", "pairwise", "https://test.com");

        Subject subject1 =
                ClientSubjectHelper.getSubject(userProfile, clientRegistry1, authenticationService);
        Subject subject2 =
                ClientSubjectHelper.getSubject(userProfile, clientRegistry2, authenticationService);

        assertEquals(subject1, subject2);
    }

    @Test
    void shouldReturnSameSubjectIDForMultipleClientsWithPublicSubjectType() {
        KeyPair keyPair = generateRsaKeyPair();
        UserProfile userProfile = generateUserProfile();

        ClientRegistry clientRegistry1 =
                generateClientRegistryPairwise(
                        keyPair, "test-client-id-1", "public", "https://test.com");
        ClientRegistry clientRegistry2 =
                generateClientRegistryPairwise(
                        keyPair, "test-client-id-2", "public", "https://test.com");

        Subject subject1 =
                ClientSubjectHelper.getSubject(userProfile, clientRegistry1, authenticationService);
        Subject subject2 =
                ClientSubjectHelper.getSubject(userProfile, clientRegistry2, authenticationService);

        assertEquals(subject1, subject2);
    }

    @Test
    void shouldReturnSubjectIDAsURIWhenClientTypeIsPairwise() {
        stubAuthenticationService();
        var keyPair = generateRsaKeyPair();
        var userProfile = generateUserProfile();

        var clientRegistry1 =
                generateClientRegistryPairwise(
                        keyPair, "test-client-id-1", "pairwise", "https://test.com");

        var subject =
                ClientSubjectHelper.getSubject(userProfile, clientRegistry1, authenticationService);

        assertTrue(subject.getValue().startsWith("urn:uuid:"));
    }

    @Test
    void shouldNotReturnSubjectIDAsURIWhenClientTypeIsPublic() {
        stubAuthenticationService();
        var keyPair = generateRsaKeyPair();
        var userProfile = generateUserProfile();

        var clientRegistry1 =
                generateClientRegistryPairwise(
                        keyPair, "test-client-id-1", "public", "https://test.com");

        var subject =
                ClientSubjectHelper.getSubject(userProfile, clientRegistry1, authenticationService);

        assertFalse(subject.getValue().startsWith("urn:uuid:"));
    }

    @Test
    void shouldGetHostAsSectorIdentierWhenDefinedByClient() {
        KeyPair keyPair = generateRsaKeyPair();
        ClientRegistry clientRegistry1 =
                generateClientRegistryPairwise(
                        keyPair, "test-client-id-1", "public", "https://test.com");

        String sectorId = ClientSubjectHelper.getSectorIdentifierForClient(clientRegistry1);

        assertEquals("test.com", sectorId);
    }

    @Test
    void shouldGetRedirectHostWhenSectorIdentierNotDefinedByClient() {
        KeyPair keyPair = generateRsaKeyPair();
        ClientRegistry clientRegistry1 =
                generateClientRegistryPairwise(keyPair, "test-client-id-1", "public", null);

        String sectorId = ClientSubjectHelper.getSectorIdentifierForClient(clientRegistry1);

        assertEquals("localhost", sectorId);
    }

    @Test
    void shouldThrowExceptionWhenClientConfigSectorIdInvalid() {
        KeyPair keyPair = generateRsaKeyPair();
        ClientRegistry clientRegistry1 =
                generateClientRegistryPairwise(
                        keyPair,
                        "test-client-id-1",
                        "public",
                        null,
                        List.of("https://www.test.com", "https://www.test2.com"));

        assertThrows(
                RuntimeException.class,
                () -> ClientSubjectHelper.getSectorIdentifierForClient(clientRegistry1),
                "Expected to throw exception");
    }

    @Test
    void shouldReturnHostForValidSectorUri() {
        assertEquals("test.com", ClientSubjectHelper.returnHost("https://test.com/hello"));
    }

    @Test
    void shouldReturnHostForValidSectorUriStartingWWW() {
        assertEquals("test.com", ClientSubjectHelper.returnHost("https://www.test.com/hello"));
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
        KeyPair keyPair = generateRsaKeyPair();
        ClientRegistry clientRegistry1 =
                generateClientRegistryPairwise(keyPair, "test-client-id-1", "public", null);

        assertTrue(ClientSubjectHelper.hasValidClientConfig(clientRegistry1));
    }

    @Test
    void shouldBeValidClientWithSectorId() {
        KeyPair keyPair = generateRsaKeyPair();
        ClientRegistry clientRegistry1 =
                generateClientRegistryPairwise(
                        keyPair, "test-client-id-1", "public", "https://test.com");

        assertTrue(ClientSubjectHelper.hasValidClientConfig(clientRegistry1));
    }

    @Test
    void shouldBeValidClientWithSectorIdAndTwoRedirectHosts() {
        KeyPair keyPair = generateRsaKeyPair();
        ClientRegistry clientRegistry1 =
                generateClientRegistryPairwise(
                        keyPair,
                        "test-client-id-1",
                        "public",
                        "https://test.com",
                        List.of("https://www.test.com", "https://www.test2.com"));

        assertTrue(ClientSubjectHelper.hasValidClientConfig(clientRegistry1));
    }

    @Test
    void shouldBeInvalidClientWithoutSectorIdAndTwoRedirectHosts() {
        KeyPair keyPair = generateRsaKeyPair();
        ClientRegistry clientRegistry1 =
                generateClientRegistryPairwise(
                        keyPair,
                        "test-client-id-1",
                        "public",
                        null,
                        List.of("https://www.test.com", "https://www.test2.com"));

        assertFalse(ClientSubjectHelper.hasValidClientConfig(clientRegistry1));
    }

    @Test
    void shouldBeValidClientWithoutSectorIdAndOneRedirectHostsWithTwoRedirectUris() {
        KeyPair keyPair = generateRsaKeyPair();
        ClientRegistry clientRegistry1 =
                generateClientRegistryPairwise(
                        keyPair,
                        "test-client-id-1",
                        "public",
                        null,
                        List.of("https://www.test.com/1", "https://www.test.com/2"));

        assertTrue(ClientSubjectHelper.hasValidClientConfig(clientRegistry1));
    }

    private KeyPair generateRsaKeyPair() {
        KeyPairGenerator kpg;
        try {
            kpg = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException();
        }
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    private ClientRegistry generateClientRegistryPairwise(
            KeyPair keyPair, String clientID, String subjectType, String sector) {
        return generateClientRegistryPairwise(
                keyPair, clientID, subjectType, sector, singletonList(REDIRECT_URI));
    }

    private ClientRegistry generateClientRegistryPairwise(
            KeyPair keyPair,
            String clientID,
            String subjectType,
            String sector,
            List<String> redirectUrls) {
        return new ClientRegistry()
                .setClientID(clientID)
                .setClientName("test-client")
                .setRedirectUrls(redirectUrls)
                .setScopes(SCOPES.toStringList())
                .setContacts(singletonList(TEST_EMAIL))
                .setPublicKey(
                        Base64.getMimeEncoder().encodeToString(keyPair.getPublic().getEncoded()))
                .setSectorIdentifierUri(sector)
                .setSubjectType(subjectType);
    }

    private UserProfile generateUserProfile() {
        Set<String> claims = ValidScopes.getClaimsForListOfScopes(SCOPES.toStringList());
        return new UserProfile()
                .setEmail(TEST_EMAIL)
                .setEmailVerified(true)
                .setPhoneNumber(PHONE_NUMBER)
                .setPhoneNumberVerified(true)
                .setSubjectID(INTERNAL_SUBJECT.getValue())
                .setCreated(LocalDateTime.now().toString())
                .setUpdated(LocalDateTime.now().toString())
                .setPublicSubjectID(PUBLIC_SUBJECT.getValue())
                .setClientConsent(
                        new ClientConsent(
                                CLIENT_ID, claims, LocalDateTime.now(ZoneId.of("UTC")).toString()));
    }

    private void stubAuthenticationService() {
        when(authenticationService.getOrGenerateSalt(any(UserProfile.class)))
                .thenReturn("a-test-salt".getBytes(StandardCharsets.UTF_8));
    }
}

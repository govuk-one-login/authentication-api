package uk.gov.di.orchestration.shared.helpers;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.UserProfile;
import uk.gov.di.orchestration.shared.entity.ValidScopes;
import uk.gov.di.orchestration.shared.services.AuthenticationService;
import uk.gov.di.orchestration.sharedtest.helper.KeyPairHelper;

import java.security.KeyPair;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.List;
import java.util.Set;

import static com.nimbusds.openid.connect.sdk.SubjectType.PAIRWISE;
import static com.nimbusds.openid.connect.sdk.SubjectType.PUBLIC;
import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ClientSubjectHelperTest {

    private static final String TEST_EMAIL = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String PHONE_NUMBER = "01234567890";
    private static final String REDIRECT_URI = "http://localhost/redirect";
    private static final String INTERNAL_SECTOR_URI = "https://test.account.gov.uk";
    private static final Subject INTERNAL_SUBJECT = new Subject();
    private static final Subject PUBLIC_SUBJECT = new Subject();
    private static final String CLIENT_ID = "test-id";
    private static final Scope SCOPES =
            new Scope(OIDCScopeValue.OPENID, OIDCScopeValue.EMAIL, OIDCScopeValue.OFFLINE_ACCESS);
    private KeyPair keyPair;
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final UserProfile userProfile = generateUserProfile();

    @BeforeEach
    void setUp() {
        keyPair = KeyPairHelper.GENERATE_RSA_KEY_PAIR();
        when(authenticationService.getOrGenerateSalt(userProfile))
                .thenReturn(SaltHelper.generateNewSalt());
    }

    @Test
    void shouldReturnDifferentSubjectIDForMultipleClientsWithDifferentSectors() {
        ClientRegistry clientRegistry1 =
                generateClientRegistryPairwise(
                        keyPair,
                        "test-client-id-1",
                        PAIRWISE.toString(),
                        "https://test.com",
                        false);
        ClientRegistry clientRegistry2 =
                generateClientRegistryPairwise(
                        keyPair,
                        "test-client-id-2",
                        PAIRWISE.toString(),
                        "https://not-test.com",
                        false);

        Subject subject1 =
                ClientSubjectHelper.getSubject(
                        userProfile, clientRegistry1, authenticationService, INTERNAL_SECTOR_URI);
        Subject subject2 =
                ClientSubjectHelper.getSubject(
                        userProfile, clientRegistry2, authenticationService, INTERNAL_SECTOR_URI);

        assertNotEquals(subject1, subject2);
    }

    @Test
    void shouldReturnSameSubjectIDForMultipleClientsWithSameSector() {
        var clientRegistry1 =
                generateClientRegistryPairwise(
                        keyPair,
                        "test-client-id-1",
                        PAIRWISE.toString(),
                        "https://test.com",
                        false);
        var clientRegistry2 =
                generateClientRegistryPairwise(
                        keyPair,
                        "test-client-id-2",
                        PAIRWISE.toString(),
                        "https://test.com",
                        false);

        var subject1 =
                ClientSubjectHelper.getSubject(
                        userProfile, clientRegistry1, authenticationService, INTERNAL_SECTOR_URI);
        var subject2 =
                ClientSubjectHelper.getSubject(
                        userProfile, clientRegistry2, authenticationService, INTERNAL_SECTOR_URI);

        assertEquals(subject1, subject2);
    }

    @Test
    void shouldReturnSameSubjectIDForMultipleClientsWithPublicSubjectType() {
        ClientRegistry clientRegistry1 =
                generateClientRegistryPairwise(
                        keyPair, "test-client-id-1", PUBLIC.toString(), "https://test.com", false);
        ClientRegistry clientRegistry2 =
                generateClientRegistryPairwise(
                        keyPair, "test-client-id-2", PUBLIC.toString(), "https://test.com", false);

        Subject subject1 =
                ClientSubjectHelper.getSubject(
                        userProfile, clientRegistry1, authenticationService, INTERNAL_SECTOR_URI);
        Subject subject2 =
                ClientSubjectHelper.getSubject(
                        userProfile, clientRegistry2, authenticationService, INTERNAL_SECTOR_URI);

        assertThat(subject1, equalTo(PUBLIC_SUBJECT));
        assertThat(subject2, equalTo(PUBLIC_SUBJECT));
    }

    @Test
    void shouldReturnPairwiseSubjectIdWhenClientTypeIsPairwise() {
        var clientRegistry1 =
                generateClientRegistryPairwise(
                        keyPair,
                        "test-client-id-1",
                        PAIRWISE.toString(),
                        "https://test.com",
                        false);

        var subject =
                ClientSubjectHelper.getSubject(
                        userProfile, clientRegistry1, authenticationService, INTERNAL_SECTOR_URI);

        assertTrue(subject.getValue().startsWith("urn:fdc:gov.uk:2022:"));
    }

    @Test
    void shouldReturnPairwiseSubjectIdWhenClientTypeIsPairwiseAndIsAOneLoginService() {
        var clientRegistry1 =
                generateClientRegistryPairwise(
                        keyPair, "test-client-id-1", PAIRWISE.toString(), "https://test.com", true);
        var clientRegistry2 =
                generateClientRegistryPairwise(
                        keyPair,
                        "test-client-id-1",
                        PAIRWISE.toString(),
                        "https://test.com",
                        false);

        var subject =
                ClientSubjectHelper.getSubject(
                        userProfile, clientRegistry1, authenticationService, INTERNAL_SECTOR_URI);
        var subject2 =
                ClientSubjectHelper.getSubject(
                        userProfile, clientRegistry2, authenticationService, INTERNAL_SECTOR_URI);

        assertTrue(subject.getValue().startsWith("urn:fdc:gov.uk:2022:"));
        assertThat(subject, not(subject2));
    }

    @Test
    void shouldNotReturnPairwiseSubjectIdWhenClientTypeIsPublic() {
        var clientRegistry1 =
                generateClientRegistryPairwise(
                        keyPair, "test-client-id-1", PUBLIC.toString(), "https://test.com", false);

        var subject =
                ClientSubjectHelper.getSubject(
                        userProfile, clientRegistry1, authenticationService, INTERNAL_SECTOR_URI);

        assertFalse(subject.getValue().startsWith("urn:fdc:gov.uk:2022:"));
        assertThat(subject.getValue(), equalTo(PUBLIC_SUBJECT.getValue()));
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

    private UserProfile generateUserProfile() {
        Set<String> claims = ValidScopes.getClaimsForListOfScopes(SCOPES.toStringList());
        return new UserProfile()
                .withEmail(TEST_EMAIL)
                .withEmailVerified(true)
                .withPhoneNumber(PHONE_NUMBER)
                .withPhoneNumberVerified(true)
                .withSubjectID(INTERNAL_SUBJECT.getValue())
                .withCreated(LocalDateTime.now().toString())
                .withUpdated(LocalDateTime.now().toString())
                .withPublicSubjectID(PUBLIC_SUBJECT.getValue());
    }
}

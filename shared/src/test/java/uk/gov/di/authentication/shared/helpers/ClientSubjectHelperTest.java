package uk.gov.di.authentication.shared.helpers;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.services.AuthenticationService;

import java.time.LocalDateTime;
import java.util.List;

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
    private static final String CLIENT_ID_1 = "test-client-id-1";
    private static final String CLIENT_ID_2 = "test-client-id-2";
    private static final String SECTOR_HOST = "test.com";
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final UserProfile userProfile = generateUserProfile();

    @BeforeEach
    void setUp() {
        when(authenticationService.getOrGenerateSalt(userProfile))
                .thenReturn(SaltHelper.generateNewSalt());
    }

    @Test
    void shouldReturnDifferentSubjectIDForMultipleClientsWithDifferentSectors() {
        var clientRegistry1 = createClient(CLIENT_ID_1, PAIRWISE.toString(), SECTOR_HOST, false);
        var authSession1 = createSession(CLIENT_ID_1, PAIRWISE.toString(), SECTOR_HOST, false);
        var clientRegistry2 = createClient(CLIENT_ID_2, PAIRWISE.toString(), "not.test.com", false);
        var authSession2 = createSession(CLIENT_ID_2, PAIRWISE.toString(), "not.test.com", false);

        Subject subject1 =
                ClientSubjectHelper.getSubject(
                        userProfile,
                        clientRegistry1,
                        authSession1,
                        authenticationService,
                        INTERNAL_SECTOR_URI);
        Subject subject2 =
                ClientSubjectHelper.getSubject(
                        userProfile,
                        clientRegistry2,
                        authSession2,
                        authenticationService,
                        INTERNAL_SECTOR_URI);

        assertNotEquals(subject1, subject2);
    }

    @Test
    void shouldReturnSameSubjectIDForMultipleClientsWithSameSector() {
        var clientRegistry1 = createClient(CLIENT_ID_1, PAIRWISE.toString(), SECTOR_HOST, false);
        var authSession1 = createSession(CLIENT_ID_1, PAIRWISE.toString(), SECTOR_HOST, false);
        var clientRegistry2 = createClient(CLIENT_ID_2, PAIRWISE.toString(), SECTOR_HOST, false);
        var authSession2 = createSession(CLIENT_ID_2, PAIRWISE.toString(), SECTOR_HOST, false);

        Subject subject1 =
                ClientSubjectHelper.getSubject(
                        userProfile,
                        clientRegistry1,
                        authSession1,
                        authenticationService,
                        INTERNAL_SECTOR_URI);
        Subject subject2 =
                ClientSubjectHelper.getSubject(
                        userProfile,
                        clientRegistry2,
                        authSession2,
                        authenticationService,
                        INTERNAL_SECTOR_URI);

        assertEquals(subject1, subject2);
    }

    @Test
    void shouldReturnSameSubjectIDForMultipleClientsWithPublicSubjectType() {
        var clientRegistry1 = createClient(CLIENT_ID_1, PUBLIC.toString(), SECTOR_HOST, false);
        var authSession1 = createSession(CLIENT_ID_1, PUBLIC.toString(), SECTOR_HOST, false);
        var clientRegistry2 = createClient(CLIENT_ID_2, PUBLIC.toString(), "not.test.com", false);
        var authSession2 = createSession(CLIENT_ID_2, PUBLIC.toString(), "not.test.com", false);

        Subject subject1 =
                ClientSubjectHelper.getSubject(
                        userProfile,
                        clientRegistry1,
                        authSession1,
                        authenticationService,
                        INTERNAL_SECTOR_URI);
        Subject subject2 =
                ClientSubjectHelper.getSubject(
                        userProfile,
                        clientRegistry2,
                        authSession2,
                        authenticationService,
                        INTERNAL_SECTOR_URI);

        assertThat(subject1, equalTo(PUBLIC_SUBJECT));
        assertThat(subject2, equalTo(PUBLIC_SUBJECT));
    }

    @Test
    void shouldReturnPairwiseSubjectIdWhenClientTypeIsPairwise() {
        var clientRegistry = createClient(CLIENT_ID_1, PAIRWISE.toString(), SECTOR_HOST, false);
        var authSession = createSession(CLIENT_ID_1, PAIRWISE.toString(), SECTOR_HOST, false);

        var subject =
                ClientSubjectHelper.getSubject(
                        userProfile,
                        clientRegistry,
                        authSession,
                        authenticationService,
                        INTERNAL_SECTOR_URI);

        assertTrue(subject.getValue().startsWith("urn:fdc:gov.uk:2022:"));
    }

    @Test
    void shouldReturnPairwiseSubjectIdWhenClientTypeIsPairwiseAndIsAOneLoginService() {
        var clientRegistry1 = createClient(CLIENT_ID_1, PAIRWISE.toString(), SECTOR_HOST, true);
        var authSession1 = createSession(CLIENT_ID_1, PAIRWISE.toString(), SECTOR_HOST, true);
        var clientRegistry2 = createClient(CLIENT_ID_2, PAIRWISE.toString(), SECTOR_HOST, false);
        var authSession2 = createSession(CLIENT_ID_2, PAIRWISE.toString(), SECTOR_HOST, false);

        var subject1 =
                ClientSubjectHelper.getSubject(
                        userProfile,
                        clientRegistry1,
                        authSession1,
                        authenticationService,
                        INTERNAL_SECTOR_URI);
        var subject2 =
                ClientSubjectHelper.getSubject(
                        userProfile,
                        clientRegistry2,
                        authSession2,
                        authenticationService,
                        INTERNAL_SECTOR_URI);

        assertTrue(subject1.getValue().startsWith("urn:fdc:gov.uk:2022:"));
        assertThat(subject1, not(subject2));
    }

    @Test
    void shouldNotReturnPairwiseSubjectIdWhenClientTypeIsPublic() {
        var clientRegistry = createClient(CLIENT_ID_1, PUBLIC.toString(), SECTOR_HOST, false);
        var authSession = createSession(CLIENT_ID_1, PUBLIC.toString(), SECTOR_HOST, false);

        var subject =
                ClientSubjectHelper.getSubject(
                        userProfile,
                        clientRegistry,
                        authSession,
                        authenticationService,
                        INTERNAL_SECTOR_URI);

        assertFalse(subject.getValue().startsWith("urn:fdc:gov.uk:2022:"));
        assertThat(subject.getValue(), equalTo(PUBLIC_SUBJECT.getValue()));
    }

    @Test
    void shouldGetHostAsSectorIdentifierWhenDefinedByClient() {
        var clientRegistry = createClient(CLIENT_ID_1, PUBLIC.toString(), SECTOR_HOST, false);
        var authSession = createSession(CLIENT_ID_1, PUBLIC.toString(), SECTOR_HOST, false);

        var sectorId =
                ClientSubjectHelper.getSectorIdentifierForClient(
                        clientRegistry, authSession, INTERNAL_SECTOR_URI);

        assertThat(sectorId, equalTo(SECTOR_HOST));
    }

    @Test
    void shouldGetHostOfInternalSectorUriWhenClientIsOneLoginService() {
        var clientRegistry = createClient(CLIENT_ID_1, PUBLIC.toString(), null, true);
        var authSession = createSession(CLIENT_ID_1, PUBLIC.toString(), null, true);

        var sectorId =
                ClientSubjectHelper.getSectorIdentifierForClient(
                        clientRegistry, authSession, INTERNAL_SECTOR_URI);

        assertThat(sectorId, equalTo("test.account.gov.uk"));
    }

    @Test
    void shouldUseHostOfInternalSectorUriWhenOneLoginServiceAndClientHasRegisteredSector() {
        var clientRegistry = createClient(CLIENT_ID_1, PUBLIC.toString(), SECTOR_HOST, true);
        var authSession = createSession(CLIENT_ID_1, PUBLIC.toString(), SECTOR_HOST, true);

        var sectorId =
                ClientSubjectHelper.getSectorIdentifierForClient(
                        clientRegistry, authSession, INTERNAL_SECTOR_URI);

        assertThat(sectorId, equalTo("test.account.gov.uk"));
    }

    @Test
    void shouldCalculateHostFromRedirectUriWhenSectorUriIsNotDefinedByClient() {
        var clientRegistry = createClient(CLIENT_ID_1, PUBLIC.toString(), null, false);
        var authSession = createSession(CLIENT_ID_1, PUBLIC.toString(), null, false);

        var sectorId =
                ClientSubjectHelper.getSectorIdentifierForClient(
                        clientRegistry, authSession, INTERNAL_SECTOR_URI);

        assertThat(sectorId, equalTo("localhost"));
    }

    @Test
    void shouldThrowExceptionWhenClientConfigSectorIdInvalid() {
        var clientRegistry =
                createClient(
                        CLIENT_ID_1,
                        PUBLIC.toString(),
                        null,
                        List.of("https://www.test.com", "https://www.test2.com"),
                        false);
        var authSession = createSession(CLIENT_ID_1, PUBLIC.toString(), null, false);

        assertThrows(
                RuntimeException.class,
                () ->
                        ClientSubjectHelper.getSectorIdentifierForClient(
                                clientRegistry, authSession, INTERNAL_SECTOR_URI),
                "Expected to throw exception");
    }

    @Test
    void shouldReturnHostForValidSectorUri() {
        assertThat(ClientSubjectHelper.returnHost("https://test.com/hello"), equalTo(SECTOR_HOST));
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
                ClientSubjectHelper.returnHost("https://www.test.com/hello"), equalTo(SECTOR_HOST));
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
        var clientRegistry = createClient(CLIENT_ID_1, PUBLIC.toString(), null, false);

        assertTrue(ClientSubjectHelper.hasValidClientConfig(clientRegistry));
    }

    @Test
    void shouldBeValidClientWithSectorId() {
        var clientRegistry = createClient(CLIENT_ID_1, PUBLIC.toString(), SECTOR_HOST, false);

        assertTrue(ClientSubjectHelper.hasValidClientConfig(clientRegistry));
    }

    @Test
    void shouldBeValidClientWithSectorIdAndTwoRedirectHosts() {
        var clientRegistry =
                createClient(
                        CLIENT_ID_1,
                        PUBLIC.toString(),
                        SECTOR_HOST,
                        List.of("https://www.test.com", "https://www.test2.com"),
                        false);

        assertTrue(ClientSubjectHelper.hasValidClientConfig(clientRegistry));
    }

    @Test
    void shouldBeInvalidClientWithoutSectorIdAndTwoRedirectHosts() {
        var clientRegistry =
                createClient(
                        CLIENT_ID_1,
                        PUBLIC.toString(),
                        null,
                        List.of("https://www.test.com", "https://www.test2.com"),
                        false);

        assertFalse(ClientSubjectHelper.hasValidClientConfig(clientRegistry));
    }

    @Test
    void shouldBeValidClientWithoutSectorIdAndOneRedirectHostsWithTwoRedirectUris() {
        var clientRegistry =
                createClient(
                        CLIENT_ID_1,
                        PUBLIC.toString(),
                        null,
                        List.of("https://www.test.com/1", "https://www.test.com/2"),
                        false);

        assertTrue(ClientSubjectHelper.hasValidClientConfig(clientRegistry));
    }

    private ClientRegistry createClient(
            String clientID, String subjectType, String sectorHost, boolean oneLoginService) {
        return createClient(
                clientID, subjectType, sectorHost, singletonList(REDIRECT_URI), oneLoginService);
    }

    private ClientRegistry createClient(
            String clientID,
            String subjectType,
            String sectorHost,
            List<String> redirectUrls,
            boolean oneLoginService) {
        return new ClientRegistry()
                .withClientID(clientID)
                .withClientName("test-client")
                .withRedirectUrls(redirectUrls)
                .withScopes(
                        new Scope(
                                        OIDCScopeValue.OPENID,
                                        OIDCScopeValue.EMAIL,
                                        OIDCScopeValue.OFFLINE_ACCESS)
                                .toStringList())
                .withContacts(singletonList(TEST_EMAIL))
                .withSectorIdentifierUri(sectorHost != null ? "https://" + sectorHost : null)
                .withOneLoginService(oneLoginService)
                .withSubjectType(subjectType);
    }

    private UserProfile generateUserProfile() {
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

    private static AuthSessionItem createSession(
            String clientID, String subjectType, String sectorHost, boolean oneLoginService) {
        return new AuthSessionItem()
                .withSessionId(IdGenerator.generate())
                .withClientId(clientID)
                .withSubjectType(subjectType)
                .withRpSectorIdentifierHost(sectorHost)
                .withIsOneLoginService(oneLoginService);
    }
}

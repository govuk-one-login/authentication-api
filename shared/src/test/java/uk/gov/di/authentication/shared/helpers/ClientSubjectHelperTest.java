package uk.gov.di.authentication.shared.helpers;

import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.services.AuthenticationService;

import java.time.LocalDateTime;

import static com.nimbusds.openid.connect.sdk.SubjectType.PAIRWISE;
import static com.nimbusds.openid.connect.sdk.SubjectType.PUBLIC;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
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
        var authSession1 = createSession(CLIENT_ID_1, PAIRWISE.toString(), SECTOR_HOST, false);
        var authSession2 = createSession(CLIENT_ID_2, PAIRWISE.toString(), "not.test.com", false);

        Subject subject1 =
                ClientSubjectHelper.getSubject(userProfile, authSession1, authenticationService);
        Subject subject2 =
                ClientSubjectHelper.getSubject(userProfile, authSession2, authenticationService);

        assertNotEquals(subject1, subject2);
    }

    @Test
    void shouldReturnSameSubjectIDForMultipleClientsWithSameSector() {
        var authSession1 = createSession(CLIENT_ID_1, PAIRWISE.toString(), SECTOR_HOST, false);
        var authSession2 = createSession(CLIENT_ID_2, PAIRWISE.toString(), SECTOR_HOST, false);

        Subject subject1 =
                ClientSubjectHelper.getSubject(userProfile, authSession1, authenticationService);
        Subject subject2 =
                ClientSubjectHelper.getSubject(userProfile, authSession2, authenticationService);

        assertEquals(subject1, subject2);
    }

    @Test
    void shouldReturnSameSubjectIDForMultipleClientsWithPublicSubjectType() {
        var authSession1 = createSession(CLIENT_ID_1, PUBLIC.toString(), SECTOR_HOST, false);
        var authSession2 = createSession(CLIENT_ID_2, PUBLIC.toString(), "not.test.com", false);

        Subject subject1 =
                ClientSubjectHelper.getSubject(userProfile, authSession1, authenticationService);
        Subject subject2 =
                ClientSubjectHelper.getSubject(userProfile, authSession2, authenticationService);

        assertThat(subject1, equalTo(PUBLIC_SUBJECT));
        assertThat(subject2, equalTo(PUBLIC_SUBJECT));
    }

    @Test
    void shouldReturnPairwiseSubjectIdWhenClientTypeIsPairwise() {
        var authSession = createSession(CLIENT_ID_1, PAIRWISE.toString(), SECTOR_HOST, false);

        var subject =
                ClientSubjectHelper.getSubject(userProfile, authSession, authenticationService);

        assertTrue(subject.getValue().startsWith("urn:fdc:gov.uk:2022:"));
    }

    @Test
    void shouldNotReturnPairwiseSubjectIdWhenClientTypeIsPublic() {
        var authSession = createSession(CLIENT_ID_1, PUBLIC.toString(), SECTOR_HOST, false);

        var subject =
                ClientSubjectHelper.getSubject(userProfile, authSession, authenticationService);

        assertFalse(subject.getValue().startsWith("urn:fdc:gov.uk:2022:"));
        assertThat(subject.getValue(), equalTo(PUBLIC_SUBJECT.getValue()));
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

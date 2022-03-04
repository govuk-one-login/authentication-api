package uk.gov.di.authentication.shared.helpers;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.ClientConsent;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.ValidScopes;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Base64;
import java.util.Set;

import static java.util.Collections.singletonList;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class ClientSubjectHelperTest {

    private static final String TEST_EMAIL = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String PHONE_NUMBER = "01234567890";
    private static final String REDIRECT_URI = "http://localhost/redirect";
    private static final Subject INTERNAL_SUBJECT = new Subject();
    private static final Subject PUBLIC_SUBJECT = new Subject();
    private static final String CLIENT_ID = "test-id";
    private static final Scope SCOPES =
            new Scope(OIDCScopeValue.OPENID, OIDCScopeValue.EMAIL, OIDCScopeValue.OFFLINE_ACCESS);

    @Test
    void shouldReturnDifferentSubjectIDForMultipleClientsWithDifferentSectors() {
        KeyPair keyPair = generateRsaKeyPair();
        UserProfile userProfile = generateUserProfile();

        ClientRegistry clientRegistry1 =
                generateClientRegistryPairwise(
                        keyPair, "test-client-id-1", "pairwise", "https://test.com");
        ClientRegistry clientRegistry2 =
                generateClientRegistryPairwise(
                        keyPair, "test-client-id-2", "pairwise", "https://not-test.com");

        Subject subject1 = ClientSubjectHelper.getSubject(userProfile, clientRegistry1);
        Subject subject2 = ClientSubjectHelper.getSubject(userProfile, clientRegistry2);

        assertNotEquals(subject1, subject2);
    }

    @Test
    void
            shouldReturnSameSubjectIDAndGenerateNewUserSaltForMultipleClientsWithSameSectorWhenUserHasNoSalt() {
        KeyPair keyPair = generateRsaKeyPair();
        UserProfile userProfile = generateUserProfile();

        ClientRegistry clientRegistry1 =
                generateClientRegistryPairwise(
                        keyPair, "test-client-id-1", "pairwise", "https://test.com");
        ClientRegistry clientRegistry2 =
                generateClientRegistryPairwise(
                        keyPair, "test-client-id-2", "pairwise", "https://test.com");

        Subject subject1 = ClientSubjectHelper.getSubject(userProfile, clientRegistry1);
        Subject subject2 = ClientSubjectHelper.getSubject(userProfile, clientRegistry2);

        assertEquals(subject1, subject2);
        assertNotNull(userProfile.getSalt());
        assertEquals(32, Base64.getDecoder().decode(userProfile.getSalt()).length);
    }

    @Test
    void
            shouldReturnSameSubjectIDAndKeepExistingUserSaltForMultipleClientsWithSameSectorWhenUserHasPreexistingSalt() {
        KeyPair keyPair = generateRsaKeyPair();
        final String SALT_VALUE = "a-pre-existing-salt-value";
        byte[] salt = SALT_VALUE.getBytes(StandardCharsets.UTF_8);
        UserProfile userProfile = generateUserProfile(Base64.getEncoder().encodeToString(salt));

        ClientRegistry clientRegistry1 =
                generateClientRegistryPairwise(
                        keyPair, "test-client-id-1", "pairwise", "https://test.com");
        ClientRegistry clientRegistry2 =
                generateClientRegistryPairwise(
                        keyPair, "test-client-id-2", "pairwise", "https://test.com");

        Subject subject1 = ClientSubjectHelper.getSubject(userProfile, clientRegistry1);
        Subject subject2 = ClientSubjectHelper.getSubject(userProfile, clientRegistry2);

        assertEquals(subject1, subject2);
        assertEquals(SALT_VALUE, new String(Base64.getDecoder().decode(userProfile.getSalt())));
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

        Subject subject1 = ClientSubjectHelper.getSubject(userProfile, clientRegistry1);
        Subject subject2 = ClientSubjectHelper.getSubject(userProfile, clientRegistry2);

        assertEquals(subject1, subject2);
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
            KeyPair keyPair, String clientID, String subectType, String sector) {
        return new ClientRegistry()
                .setClientID(clientID)
                .setClientName("test-client")
                .setRedirectUrls(singletonList(REDIRECT_URI))
                .setScopes(SCOPES.toStringList())
                .setContacts(singletonList(TEST_EMAIL))
                .setPublicKey(
                        Base64.getMimeEncoder().encodeToString(keyPair.getPublic().getEncoded()))
                .setSectorIdentifierUri(sector)
                .setSubjectType(subectType);
    }

    private UserProfile generateUserProfile() {
        return generateUserProfile(null);
    }

    private UserProfile generateUserProfile(String salt) {
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
                .setSalt(salt)
                .setClientConsent(
                        new ClientConsent(
                                CLIENT_ID, claims, LocalDateTime.now(ZoneId.of("UTC")).toString()));
    }
}

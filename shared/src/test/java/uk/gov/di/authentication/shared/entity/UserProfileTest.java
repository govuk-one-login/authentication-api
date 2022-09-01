package uk.gov.di.authentication.shared.entity;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import uk.gov.di.authentication.shared.helpers.NowHelper;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

class UserProfileTest {

    private static final String EMAIL = "user.one@test.com";
    private static final String PHONE_NUMBER = "01234567890";
    private static final String CLIENT_ID = "client-id";
    private static final Date CREATED_DATE_TIME = NowHelper.nowMinus(30, ChronoUnit.SECONDS);
    private static final Date UPDATED_DATE_TIME = NowHelper.now();
    private static final String LEGACY_SUBJECT_ID = new Subject("legacy-subject-id-1").getValue();
    private static final String PUBLIC_SUBJECT_ID = new Subject("public-subject-id-2").getValue();
    private static final String SUBJECT_ID = new Subject("subject-id-3").getValue();
    private static final TermsAndConditions TERMS_AND_CONDITIONS =
            new TermsAndConditions("1.0", CREATED_DATE_TIME.toString());
    private static final Scope SCOPES =
            new Scope(OIDCScopeValue.OPENID, OIDCScopeValue.EMAIL, OIDCScopeValue.OFFLINE_ACCESS);
    private static final Set<String> CLAIMS =
            ValidScopes.getClaimsForListOfScopes(SCOPES.toStringList());
    private static final ClientConsent CLIENT_CONSENT =
            new ClientConsent(CLIENT_ID, CLAIMS, CREATED_DATE_TIME.toString());
    private static final ByteBuffer SALT =
            ByteBuffer.wrap("a-test-salt".getBytes(StandardCharsets.UTF_8));

    @Test
    void shouldCreateUserProfile() {

        UserProfile userProfile = generateUserProfile();

        assertThat(userProfile.getEmail(), equalTo(EMAIL));
        assertThat(userProfile.getSubjectID(), equalTo(SUBJECT_ID));
        assertThat(userProfile.isEmailVerified(), equalTo(true));
        assertThat(userProfile.getPhoneNumber(), equalTo(PHONE_NUMBER));
        assertThat(userProfile.isPhoneNumberVerified(), equalTo(true));
        assertThat(userProfile.getCreated(), equalTo(CREATED_DATE_TIME.toString()));
        assertThat(userProfile.getUpdated(), equalTo(UPDATED_DATE_TIME.toString()));
        assertThat(userProfile.getTermsAndConditions(), equalTo(TERMS_AND_CONDITIONS));
        assertThat(userProfile.getClientConsent(), equalTo(List.of(CLIENT_CONSENT)));
        assertThat(userProfile.getLegacySubjectID(), equalTo(LEGACY_SUBJECT_ID));
        assertThat(userProfile.getSalt(), equalTo(SALT));
    }

    @Test
    void shouldConvertUserProfileToItem() {
        UserProfile userProfile = generateUserProfile();
        Map<String, AttributeValue> userProfileItem = userProfile.toItem();

        assertThat(
                userProfileItem.get(UserProfile.ATTRIBUTE_EMAIL).s(),
                equalTo(userProfile.getEmail()));
        assertThat(
                userProfileItem.get(UserProfile.ATTRIBUTE_SUBJECT_ID).s(),
                equalTo(userProfile.getSubjectID()));
        assertThat(
                userProfileItem.get(UserProfile.ATTRIBUTE_EMAIL_VERIFIED).n(),
                equalTo(userProfile.isEmailVerified() ? "1" : "0"));
        assertThat(
                userProfileItem.get(UserProfile.ATTRIBUTE_PHONE_NUMBER).s(),
                equalTo(userProfile.getPhoneNumber()));
        assertThat(
                userProfileItem.get(UserProfile.ATTRIBUTE_PHONE_NUMBER_VERIFIED).n(),
                equalTo(userProfile.isPhoneNumberVerified() ? "1" : "0"));
        assertThat(
                userProfileItem.get(UserProfile.ATTRIBUTE_CREATED).s(),
                equalTo(userProfile.getCreated()));
        assertThat(
                userProfileItem.get(UserProfile.ATTRIBUTE_UPDATED).s(),
                equalTo(userProfile.getUpdated()));
        assertThat(
                userProfileItem.get(UserProfile.ATTRIBUTE_TERMS_AND_CONDITIONS),
                equalTo(userProfile.getTermsAndConditions().toAttributeValue()));
        compareClientConsentList(
                userProfileItem.get(UserProfile.ATTRIBUTE_CLIENT_CONSENT).l(),
                userProfile.getClientConsent());
        assertThat(
                userProfileItem.get(UserProfile.ATTRIBUTE_LEGACY_SUBJECT_ID).s(),
                equalTo(userProfile.getLegacySubjectID()));
        assertThat(
                userProfileItem.get(UserProfile.ATTRIBUTE_SALT).b().asByteBuffer(),
                equalTo(userProfile.getSalt()));
    }

    private void compareClientConsentList(
            List<AttributeValue> attributeValueList, List<ClientConsent> clientConsents) {
        assertThat(attributeValueList.size(), equalTo(clientConsents.size()));
        for (int i = 0; i < attributeValueList.size(); i++) {
            assertThat(
                    attributeValueList.get(i), equalTo(clientConsents.get(i).toAttributeValue()));
        }
    }

    private UserProfile generateUserProfile() {
        return new UserProfile()
                .withEmail(EMAIL)
                .withEmailVerified(true)
                .withPhoneNumber(PHONE_NUMBER)
                .withPhoneNumberVerified(true)
                .withPublicSubjectID(PUBLIC_SUBJECT_ID)
                .withSubjectID(SUBJECT_ID)
                .withLegacySubjectID(LEGACY_SUBJECT_ID)
                .setClientConsent(CLIENT_CONSENT)
                .withTermsAndConditions(TERMS_AND_CONDITIONS)
                .withSalt(SALT)
                .withCreated(CREATED_DATE_TIME.toString())
                .withUpdated(UPDATED_DATE_TIME.toString());
    }
}

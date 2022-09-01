package uk.gov.di.authentication.shared.entity;

import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import uk.gov.di.authentication.shared.helpers.NowHelper;

import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

class UserCredentialsTest {

    private static final String EMAIL = "user.one@test.com";
    private static final String PASSWORD = "password123";
    private static final String MIGRATED_PASSWORD = "oldpassword";
    private static final String SUBJECT_ID = new Subject("subject-id-3").getValue();
    private static final Date CREATED_DATE_TIME = NowHelper.nowMinus(30, ChronoUnit.SECONDS);
    private static final Date UPDATED_DATE_TIME = NowHelper.now();

    @Test
    void shouldCreateUserCredentials() {
        UserCredentials userCredentials = generateUserCredentials();

        assertThat(userCredentials.getEmail(), equalTo(EMAIL));
        assertThat(userCredentials.getPassword(), equalTo(PASSWORD));
        assertThat(userCredentials.getMigratedPassword(), equalTo(MIGRATED_PASSWORD));
        assertThat(userCredentials.getSubjectID(), equalTo(SUBJECT_ID));
        assertThat(userCredentials.getCreated(), equalTo(CREATED_DATE_TIME.toString()));
        assertThat(userCredentials.getUpdated(), equalTo(UPDATED_DATE_TIME.toString()));
    }

    @Test
    void shouldConvertUserCredentialsToItem() {
        UserCredentials userCredentials = generateUserCredentials();
        Map<String, AttributeValue> userCredentialsItem = userCredentials.toItem();

        assertThat(
                userCredentialsItem.get(UserCredentials.ATTRIBUTE_EMAIL).s(),
                equalTo(userCredentials.getEmail()));
        assertThat(
                userCredentialsItem.get(UserCredentials.ATTRIBUTE_PASSWORD).s(),
                equalTo(userCredentials.getPassword()));
        assertThat(
                userCredentialsItem.get(UserCredentials.ATTRIBUTE_MIGRATED_PASSWORD).s(),
                equalTo(userCredentials.getMigratedPassword()));
        assertThat(
                userCredentialsItem.get(UserCredentials.ATTRIBUTE_SUBJECT_ID).s(),
                equalTo(userCredentials.getSubjectID()));
        assertThat(
                userCredentialsItem.get(UserCredentials.ATTRIBUTE_CREATED).s(),
                equalTo(userCredentials.getCreated()));
        assertThat(
                userCredentialsItem.get(UserCredentials.ATTRIBUTE_UPDATED).s(),
                equalTo(userCredentials.getUpdated()));
    }

    private UserCredentials generateUserCredentials() {
        return new UserCredentials()
                .withEmail(EMAIL)
                .withSubjectID(SUBJECT_ID)
                .withPassword(PASSWORD)
                .withMigratedPassword(MIGRATED_PASSWORD)
                .withCreated(CREATED_DATE_TIME.toString())
                .withUpdated(UPDATED_DATE_TIME.toString());
    }
}

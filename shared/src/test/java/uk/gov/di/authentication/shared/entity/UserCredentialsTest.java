package uk.gov.di.authentication.shared.entity;

import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.helpers.NowHelper;

import java.time.temporal.ChronoUnit;
import java.util.Date;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.*;

class UserCredentialsTest {

    private static final String SUBJECT_ID = new Subject("subject-id-3").getValue();
    private static final Date CREATED_DATE_TIME = NowHelper.nowMinus(30, ChronoUnit.SECONDS);
    private static final Date UPDATED_DATE_TIME = NowHelper.now();

    @Test
    void shouldCreateUserCredentials() {
        UserCredentials userCredentials = generateUserCredentials();

        assertThat(userCredentials.getEmail(), equalTo(EMAIL));
        assertThat(userCredentials.getPassword(), equalTo(PASSWORD));
        assertThat(userCredentials.getMigratedPassword(), equalTo(PASSWORD_OLD));
        assertThat(userCredentials.getSubjectID(), equalTo(SUBJECT_ID));
        assertThat(userCredentials.getCreated(), equalTo(CREATED_DATE_TIME.toString()));
        assertThat(userCredentials.getUpdated(), equalTo(UPDATED_DATE_TIME.toString()));
    }

    private UserCredentials generateUserCredentials() {
        return new UserCredentials()
                .withEmail(EMAIL)
                .withSubjectID(SUBJECT_ID)
                .withPassword(PASSWORD)
                .withMigratedPassword(PASSWORD_OLD)
                .withCreated(CREATED_DATE_TIME.toString())
                .withUpdated(UPDATED_DATE_TIME.toString());
    }
}

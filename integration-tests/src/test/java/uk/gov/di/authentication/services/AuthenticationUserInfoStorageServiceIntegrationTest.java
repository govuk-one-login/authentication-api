package uk.gov.di.authentication.services;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.orchestration.sharedtest.extensions.AuthenticationCallbackUserInfoStoreExtension;

import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

class AuthenticationUserInfoStorageServiceIntegrationTest {

    private static final String SUBJECT_ID = "test-subject-id";
    private static final String CLIENT_SESSION_ID = "test-client-session-id";

    @RegisterExtension
    protected static final AuthenticationCallbackUserInfoStoreExtension userInfoExtension =
            new AuthenticationCallbackUserInfoStoreExtension(180);

    @Test
    void shouldAddAndRetrieveUserInfo() throws ParseException {
        UserInfo userInfo = new UserInfo(new Subject(SUBJECT_ID));

        userInfoExtension.addAuthenticationUserInfoData(SUBJECT_ID, CLIENT_SESSION_ID, userInfo);

        Optional<UserInfo> retrievedUserInfo =
                userInfoExtension.getAuthenticationUserInfo(SUBJECT_ID, CLIENT_SESSION_ID);

        assertThat(retrievedUserInfo.isPresent(), equalTo(true));
        assertThat(retrievedUserInfo.get().getSubject().getValue(), equalTo(SUBJECT_ID));
    }

    @Test
    void shouldReturnOptionalEmptyWhenNoUserInfo() throws ParseException {
        Optional<UserInfo> retrievedUserInfo =
                userInfoExtension.getAuthenticationUserInfo(SUBJECT_ID, CLIENT_SESSION_ID);

        assertThat(retrievedUserInfo.isEmpty(), equalTo(true));
    }
}

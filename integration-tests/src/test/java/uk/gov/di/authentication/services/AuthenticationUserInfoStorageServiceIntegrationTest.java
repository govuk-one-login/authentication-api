package uk.gov.di.authentication.services;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.orchestration.shared.entity.AuthenticationUserInfo;
import uk.gov.di.orchestration.sharedtest.extensions.AuthenticationCallbackUserInfoStoreExtension;

import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

class AuthenticationUserInfoStorageServiceIntegrationTest {

    private static final String SUBJECT_ID = "test-subject-id";

    @RegisterExtension
    protected static final AuthenticationCallbackUserInfoStoreExtension userInfoExtension =
            new AuthenticationCallbackUserInfoStoreExtension(180);

    @Test
    void shouldAddAndRetrieveUserInfo() throws ParseException {
        UserInfo userInfo = new UserInfo(new Subject(SUBJECT_ID));

        userInfoExtension.addAuthenticationUserInfoData(SUBJECT_ID, userInfo);

        Optional<AuthenticationUserInfo> retrievedUserInfoData =
                userInfoExtension.getUserInfoDataBySubjectId(SUBJECT_ID);

        UserInfo retrievedUserInfo = userInfoExtension.getUserInfo(SUBJECT_ID).orElseThrow();

        assertThat(retrievedUserInfoData.isPresent(), equalTo(true));
        assertThat(retrievedUserInfoData.get().getSubjectID(), equalTo(SUBJECT_ID));

        assertThat(retrievedUserInfo.getSubject().getValue(), equalTo(SUBJECT_ID));
    }

    @Test
    void shouldReturnOptionalEmptyWhenNoUserInfo() {
        Optional<AuthenticationUserInfo> retrievedUserInfo =
                userInfoExtension.getUserInfoDataBySubjectId(SUBJECT_ID);

        assertThat(retrievedUserInfo.isEmpty(), equalTo(true));
    }
}

package uk.gov.di.authentication.services;

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
    void shouldAddAndRetrieveUserInfo() {
        UserInfo userInfo = new UserInfo(new Subject(SUBJECT_ID));

        userInfoExtension.addAuthenticationUserInfoData(SUBJECT_ID, userInfo);

        Optional<AuthenticationUserInfo> retrievedUserInfo =
                userInfoExtension.getUserInfoBySubjectId(SUBJECT_ID);

        assertThat(retrievedUserInfo.isPresent(), equalTo(true));
        assertThat(retrievedUserInfo.get().getSubjectID(), equalTo(SUBJECT_ID));
    }
}

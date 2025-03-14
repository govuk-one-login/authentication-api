package uk.gov.di.authentication.testsupport.helpers;

import com.nimbusds.oauth2.sdk.id.Subject;
import uk.gov.di.authentication.shared.entity.TermsAndConditions;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.mfaMethodManagement.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfaMethodManagement.MFAMethodType;
import uk.gov.di.authentication.shared.helpers.Argon2EncoderHelper;
import uk.gov.di.authentication.shared.helpers.SaltHelper;

import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public class BulkTestUserCsvHelper {
    public static Map<UserProfile, UserCredentials> getTestUsersProfilesAndCredentials()
            throws Exception {
        var dateTime = LocalDateTime.now().toString();

        URL testFileUrl =
                Thread.currentThread()
                        .getContextClassLoader()
                        .getResource("test_users_integration_test.txt");
        Path testFilePath = Paths.get(testFileUrl.toURI());

        String testFileContent = Files.readString(testFilePath);
        String[] testFileContentAsArray = testFileContent.split("\r?\n|\r");
        List<String> testFileContentAsArrayList =
                new ArrayList<>(Arrays.asList(testFileContentAsArray));
        testFileContentAsArrayList.removeAll(Collections.singleton(null));
        testFileContentAsArrayList.removeAll(Collections.singleton(""));
        testFileContentAsArrayList.removeAll(
                Collections.singleton(
                        "Email,Password,Phone2FA,PhoneNumber,AuthApp2FA,AuthAppSecret"));

        Map<UserProfile, UserCredentials> testUsers = new HashMap<>();
        testFileContentAsArrayList.forEach(
                testUser -> {
                    String[] testUserCsv = testUser.split(",", -1);
                    List<String> testUserCsvAsArrayList =
                            new ArrayList<>(Arrays.asList(testUserCsv));

                    testUsers.put(
                            getUserProfileFromTestUserString(testUserCsvAsArrayList, dateTime),
                            getUserCredentialsFromTestUserString(testUserCsvAsArrayList, dateTime));
                });
        return testUsers;
    }

    private static UserProfile getUserProfileFromTestUserString(
            List<String> testUser, String dateTime) {
        var emailAddress = testUser.get(0);
        boolean isPhoneSecondAuthFactor = testUser.get(2).equals("1");
        var termsAndConditions = new TermsAndConditions("XXX", dateTime);

        var userProfile =
                new UserProfile()
                        .withEmail(emailAddress.toLowerCase(Locale.ROOT))
                        .withSubjectID((new Subject()).toString())
                        .withEmailVerified(true)
                        .withCreated(dateTime)
                        .withUpdated(dateTime)
                        .withPublicSubjectID((new Subject()).toString())
                        .withTermsAndConditions(termsAndConditions)
                        .withLegacySubjectID(null);
        userProfile.setSalt(SaltHelper.generateNewSalt());
        userProfile.setTestUser(1);
        userProfile.setAccountVerified(1);

        if (isPhoneSecondAuthFactor) {
            String phoneNumber = testUser.get(3);
            userProfile.setPhoneNumber(phoneNumber);
            userProfile.setPhoneNumberVerified(true);
        }

        return userProfile;
    }

    private static UserCredentials getUserCredentialsFromTestUserString(
            List<String> testUser, String dateTime) {
        var emailAddress = testUser.get(0);
        var plainTextPassword = testUser.get(1);
        boolean isAuthAppSecondAuthFactor = testUser.get(4).equals("1");
        var hashedPassword = hashPassword(plainTextPassword);

        var userCredentials =
                new UserCredentials()
                        .withEmail(emailAddress.toLowerCase(Locale.ROOT))
                        .withSubjectID((new Subject()).toString())
                        .withPassword(hashedPassword)
                        .withCreated(dateTime)
                        .withUpdated(dateTime);
        userCredentials.setTestUser(1);

        if (isAuthAppSecondAuthFactor) {
            String authAppSecret = testUser.get(4);
            List<MFAMethod> mfaMethods = new ArrayList<>();
            var authAppMfaMethod =
                    new MFAMethod(
                            MFAMethodType.AUTH_APP.getValue(), authAppSecret, true, true, dateTime);
            mfaMethods.add(authAppMfaMethod);
            userCredentials.setMfaMethods(mfaMethods);
        }

        return userCredentials;
    }

    private static String hashPassword(String password) {
        return Argon2EncoderHelper.argon2Hash(password);
    }
}

package uk.gov.di.authentication.services;

import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.shared.entity.AuthAppMfaData;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.SmsMfaData;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoMfaMethodsService;
import uk.gov.di.authentication.sharedtest.extensions.UserStoreExtension;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class DynamoMfaMethodsServiceIntegrationTest {

    private static final String TEST_EMAIL = "joe.bloggs@example.com";
    private static final String INTERNAL_COMMON_SUBJECT_ID = "subject-1";
    private static final String PHONE_NUMBER = "+44123456789";
    private static final String AUTH_APP_CREDENTIAL = "some-credential";
    DynamoMfaMethodsService dynamoService =
            new DynamoMfaMethodsService(ConfigurationService.getInstance());

    @RegisterExtension static UserStoreExtension userStoreExtension = new UserStoreExtension();

    @BeforeEach
    void setUp() {
        userStoreExtension.signUp(
                TEST_EMAIL, "password-1", new Subject(INTERNAL_COMMON_SUBJECT_ID));
    }

    @Test
    void shouldReturnSingleSmsMethodWhenVerified() {
        userStoreExtension.addVerifiedPhoneNumber(TEST_EMAIL, PHONE_NUMBER);

        var result = dynamoService.getMfaMethods(TEST_EMAIL);

        var expectedData = new SmsMfaData(PHONE_NUMBER, true, true, PriorityIdentifier.DEFAULT, 1);
        assertEquals(result, List.of(expectedData));
    }

    @Test
    void shouldReturnSingleAuthAppMethodWhenEnabled() {
        userStoreExtension.addAuthAppMethod(TEST_EMAIL, true, true, AUTH_APP_CREDENTIAL);

        var result = dynamoService.getMfaMethods(TEST_EMAIL);

        var expectedData =
                new AuthAppMfaData(AUTH_APP_CREDENTIAL, true, true, PriorityIdentifier.DEFAULT, 1);
        assertEquals(result, List.of(expectedData));
    }

    @Test
    void authAppShouldTakePrecedenceOverSmsMethodForNonMigratedUser() {
        userStoreExtension.addVerifiedPhoneNumber(TEST_EMAIL, PHONE_NUMBER);
        userStoreExtension.addAuthAppMethod(TEST_EMAIL, true, true, AUTH_APP_CREDENTIAL);

        var result = dynamoService.getMfaMethods(TEST_EMAIL);

        var expectedData =
                new AuthAppMfaData(AUTH_APP_CREDENTIAL, true, true, PriorityIdentifier.DEFAULT, 1);
        assertEquals(List.of(expectedData), result);
    }

    @Test
    void shouldReturnNoMethodsWhenAuthAppMethodNotEnabled() {
        userStoreExtension.addAuthAppMethod(TEST_EMAIL, true, false, AUTH_APP_CREDENTIAL);

        var result = dynamoService.getMfaMethods(TEST_EMAIL);

        assertEquals(result, List.of());
    }

    @Test
    void shouldReturnNoMethodsWhenSmsMethodNotVerified() {
        userStoreExtension.setPhoneNumberAndVerificationStatus(
                TEST_EMAIL, PHONE_NUMBER, false, true);

        var result = dynamoService.getMfaMethods(TEST_EMAIL);

        assertEquals(result, List.of());
    }
}

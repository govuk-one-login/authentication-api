package uk.gov.di.accountmanagement.api;

import com.google.gson.JsonParser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.accountmanagement.lambda.MFAMethodsRetrieveHandler;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.mfaMethodManagement.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfaMethodManagement.MFAMethodType;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.UserStoreExtension;

import java.util.Collections;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.authentication.shared.services.mfa.MfaMethodsService.HARDCODED_APP_MFA_ID;
import static uk.gov.di.authentication.shared.services.mfa.MfaMethodsService.HARDCODED_SMS_MFA_ID;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;

class MfaMethodsRetrieveHandlerIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String EMAIL = "joe.bloggs+3@digital.cabinet-office.gov.uk";
    private static final String PASSWORD = "password-1";
    private static final String PHONE_NUMBER = "+441234567890";

    @RegisterExtension
    private static UserStoreExtension userStoreExtension = new UserStoreExtension();

    @BeforeEach
    void setUp() {
        ConfigurationService mfaMethodEnabledConfigurationService =
                new ConfigurationService() {
                    @Override
                    public boolean isMfaMethodManagementApiEnabled() {
                        return true;
                    }
                };
        handler = new MFAMethodsRetrieveHandler(mfaMethodEnabledConfigurationService);
    }

    @Test
    void shouldReturn200WithSmsMethodWhenUserExists() {
        var publicSubjectId = userStoreExtension.signUp(EMAIL, PASSWORD);
        userStoreExtension.addVerifiedPhoneNumber(EMAIL, PHONE_NUMBER);

        var response =
                makeRequest(
                        Optional.empty(),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of("publicSubjectId", publicSubjectId),
                        Collections.emptyMap());

        assertEquals(200, response.getStatusCode());
        var expectedResponse =
                format(
                        """
                [{
                     "mfaIdentifier": "%s",
                     "priorityIdentifier": "DEFAULT",
                     "methodVerified": true,
                     "method": {
                       "mfaMethodType": "SMS",
                       "phoneNumber": "+441234567890"
                     }
                   }]
                """,
                        HARDCODED_SMS_MFA_ID);
        var expectedResponseAsJson = JsonParser.parseString(expectedResponse).getAsJsonArray();
        assertThat(response, hasJsonBody(expectedResponseAsJson));
    }

    @Test
    void shouldReturn200WithAuthAppMethodWhenUserExists() {
        var publicSubjectId = userStoreExtension.signUp(EMAIL, PASSWORD);
        userStoreExtension.addMfaMethod(
                EMAIL, MFAMethodType.AUTH_APP, true, true, "some-credential");

        var response =
                makeRequest(
                        Optional.empty(),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of("publicSubjectId", publicSubjectId),
                        Collections.emptyMap());

        assertEquals(200, response.getStatusCode());
        var expectedResponse =
                format(
                        """
                [{
                     "mfaIdentifier": "%s",
                     "priorityIdentifier": "DEFAULT",
                     "methodVerified": true,
                     "method": {
                       "mfaMethodType": "AUTH_APP",
                       "credential": "some-credential"
                     }
                   }]
                """,
                        HARDCODED_APP_MFA_ID);
        var expectedResponseAsJson = JsonParser.parseString(expectedResponse).getAsJsonArray();
        assertThat(response, hasJsonBody(expectedResponseAsJson));
    }

    @Test
    void shouldReturn200WithMultipleMethodsWhenMigratedUserExists() {
        var publicSubjectId = userStoreExtension.signUp(EMAIL, PASSWORD);
        userStoreExtension.setMfaMethodsMigrated(EMAIL, true);

        var authAppIdentifier = "14895398-33e5-41f0-b059-811b07df348d";
        var smsIdentifier = "e2d3f441-a17f-44a3-b608-b32c129b48b4";
        var authApp =
                MFAMethod.authAppMfaMethod(
                        "some-credential",
                        true,
                        true,
                        "updated-at-time",
                        PriorityIdentifier.DEFAULT,
                        authAppIdentifier);
        var sms =
                MFAMethod.smsMfaMethod(
                        true,
                        true,
                        PHONE_NUMBER,
                        "updated-at-time",
                        PriorityIdentifier.BACKUP,
                        smsIdentifier);
        userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, authApp);
        userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, sms);

        var response =
                makeRequest(
                        Optional.empty(),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of("publicSubjectId", publicSubjectId),
                        Collections.emptyMap());

        assertEquals(200, response.getStatusCode());
        var expectedResponse =
                format(
                        """
                [{
                     "mfaIdentifier": "%s",
                     "priorityIdentifier": "DEFAULT",
                     "methodVerified": true,
                     "method": {
                       "mfaMethodType": "AUTH_APP",
                       "credential": "some-credential"
                     }
                   },
                   {
                     "mfaIdentifier": "%s",
                     "priorityIdentifier": "BACKUP",
                     "methodVerified": true,
                     "method": {
                       "mfaMethodType": "SMS",
                       "phoneNumber": "+441234567890"
                     }
                   }]
                """,
                        authAppIdentifier, smsIdentifier);
        var expectedResponseAsJson = JsonParser.parseString(expectedResponse).getAsJsonArray();
        assertThat(response, hasJsonBody(expectedResponseAsJson));
    }

    @Test
    void shouldReturn404WhenUserDoesNotExist() {
        var publicSubjectId = "userDoesNotExist";
        var response =
                makeRequest(
                        Optional.empty(),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of("publicSubjectId", publicSubjectId),
                        Collections.emptyMap());

        assertEquals(404, response.getStatusCode());
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1056));
    }
}

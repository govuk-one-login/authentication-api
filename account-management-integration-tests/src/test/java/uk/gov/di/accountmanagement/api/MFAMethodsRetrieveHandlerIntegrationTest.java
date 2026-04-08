package uk.gov.di.accountmanagement.api;

import com.google.gson.JsonParser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.accountmanagement.lambda.MFAMethodsRetrieveHandler;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;

import java.util.Collections;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;

class MFAMethodsRetrieveHandlerIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String EMAIL = "joe.bloggs+3@digital.cabinet-office.gov.uk";
    private static final String PASSWORD = "password-1";
    private static final String PHONE_NUMBER = "+447700900000";
    private static final String INTERNAL_SECTOR_HOST = "test.account.gov.uk";
    private static String testInternalSubject;
    private static String publicSubjectId;

    @BeforeEach
    void setUp() {
        publicSubjectId = userStore.signUp(EMAIL, PASSWORD);
        ConfigurationService mfaMethodEnabledConfigurationService =
                new ConfigurationService() {
                    @Override
                    public boolean isMfaMethodManagementApiEnabled() {
                        return true;
                    }
                };
        handler = new MFAMethodsRetrieveHandler(mfaMethodEnabledConfigurationService);
        byte[] salt = userStore.addSalt(EMAIL);
        testInternalSubject =
                ClientSubjectHelper.calculatePairwiseIdentifier(
                        userStore.getUserProfileFromEmail(EMAIL).get().getSubjectID(),
                        INTERNAL_SECTOR_HOST,
                        salt);
    }

    @Test
    void shouldReturn200WithSmsMethodWhenUserExists() {
        userStore.addVerifiedPhoneNumber(EMAIL, PHONE_NUMBER);

        var response =
                makeRequest(
                        Optional.empty(),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of("publicSubjectId", publicSubjectId),
                        Map.of("principalId", testInternalSubject));

        var mfaIdentifier = userStore.getUserProfileFromEmail(EMAIL).get().getMfaIdentifier();

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
                       "phoneNumber": "%s"
                     }
                   }]
                """,
                        mfaIdentifier, PHONE_NUMBER);
        var expectedResponseAsJson = JsonParser.parseString(expectedResponse).getAsJsonArray();
        assertThat(response, hasJsonBody(expectedResponseAsJson));
    }

    @Test
    void shouldReturn200WithSmsAndExistingMfaIdWhenUserExists() {
        userStore.addVerifiedPhoneNumber(EMAIL, PHONE_NUMBER);
        var mfaIdentifier = "some-identifier";
        userStore.setPhoneNumberMfaIdentifer(EMAIL, mfaIdentifier);

        var response =
                makeRequest(
                        Optional.empty(),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of("publicSubjectId", publicSubjectId),
                        Map.of("principalId", testInternalSubject));

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
                       "phoneNumber": "%s"
                     }
                   }]
                """,
                        mfaIdentifier, PHONE_NUMBER);
        var expectedResponseAsJson = JsonParser.parseString(expectedResponse).getAsJsonArray();
        assertThat(response, hasJsonBody(expectedResponseAsJson));
    }

    @Test
    void shouldReturn200WithAuthAppMethodWithGeneratedMfaIdWhenUserExists() {
        userStore.addMfaMethod(EMAIL, MFAMethodType.AUTH_APP, true, true, "some-credential");

        var response =
                makeRequest(
                        Optional.empty(),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of("publicSubjectId", publicSubjectId),
                        Map.of("principalId", testInternalSubject));

        var identifier = userStore.getMfaMethod(EMAIL).get(0).getMfaIdentifier();

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
                        identifier);
        var expectedResponseAsJson = JsonParser.parseString(expectedResponse).getAsJsonArray();
        assertThat(response, hasJsonBody(expectedResponseAsJson));
    }

    @Test
    void shouldReturn200WithAuthAppMethodAndExistingMfaIdWhenUserExists() {
        var identifier = "some-identifier";
        userStore.addAuthAppMethodWithIdentifier(EMAIL, true, true, "some-credential", identifier);

        var response =
                makeRequest(
                        Optional.empty(),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of("publicSubjectId", publicSubjectId),
                        Map.of("principalId", testInternalSubject));

        var storedIdentifier = userStore.getMfaMethod(EMAIL).get(0).getMfaIdentifier();
        assertEquals(identifier, storedIdentifier);

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
                        identifier);
        var expectedResponseAsJson = JsonParser.parseString(expectedResponse).getAsJsonArray();
        assertThat(response, hasJsonBody(expectedResponseAsJson));
    }

    @Test
    void shouldReturn200WithMultipleMethodsWhenMigratedUserExists() {
        userStore.setMfaMethodsMigrated(EMAIL, true);

        var authAppIdentifier = "14895398-33e5-41f0-b059-811b07df348d";
        var smsIdentifier = "e2d3f441-a17f-44a3-b608-b32c129b48b4";
        var authApp =
                MFAMethod.authAppMfaMethod(
                        "some-credential",
                        true,
                        true,
                        PriorityIdentifier.DEFAULT,
                        authAppIdentifier);
        var sms =
                MFAMethod.smsMfaMethod(
                        true, true, PHONE_NUMBER, PriorityIdentifier.BACKUP, smsIdentifier);
        userStore.addMfaMethodSupportingMultiple(EMAIL, authApp);
        userStore.addMfaMethodSupportingMultiple(EMAIL, sms);

        var response =
                makeRequest(
                        Optional.empty(),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of("publicSubjectId", publicSubjectId),
                        Map.of("principalId", testInternalSubject));

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
                       "phoneNumber": "%s"
                     }
                   }]
                """,
                        authAppIdentifier, smsIdentifier, PHONE_NUMBER);
        var expectedResponseAsJson = JsonParser.parseString(expectedResponse).getAsJsonArray();
        assertThat(response, hasJsonBody(expectedResponseAsJson));
    }

    @Test
    void shouldReturn404WhenUserDoesNotExist() {
        var invalidPublicSubjectId = "userDoesNotExist";
        var response =
                makeRequest(
                        Optional.empty(),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of("publicSubjectId", invalidPublicSubjectId),
                        Map.of("principalId", testInternalSubject));

        assertEquals(404, response.getStatusCode());
        assertThat(response, hasJsonBody(ErrorResponse.USER_NOT_FOUND));
    }

    @Test
    void shouldReturn401WhenPrincipalIsInvalid() {
        var response =
                makeRequest(
                        Optional.empty(),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of("publicSubjectId", publicSubjectId),
                        Map.of("principalId", "invalid-principal"));

        assertEquals(401, response.getStatusCode());
        assertThat(response, hasJsonBody(ErrorResponse.INVALID_PRINCIPAL));
    }
}

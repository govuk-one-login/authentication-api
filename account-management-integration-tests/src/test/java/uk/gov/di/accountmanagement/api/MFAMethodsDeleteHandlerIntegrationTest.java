package uk.gov.di.accountmanagement.api;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.accountmanagement.lambda.MFAMethodsDeleteHandler;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.mfaMethodManagement.AuthAppMfaData;
import uk.gov.di.authentication.shared.entity.mfaMethodManagement.MFAMethodType;
import uk.gov.di.authentication.shared.entity.mfaMethodManagement.SmsMfaData;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.UserStoreExtension;

import java.util.Collections;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;

class MFAMethodsDeleteHandlerIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String EMAIL = "joe.bloggs+3@digital.cabinet-office.gov.uk";
    private static final String PASSWORD = "password-1";
    private static final AuthAppMfaData DEFAULT_PRIORITY_AUTH_APP =
            new AuthAppMfaData(
                    "some-credential",
                    true,
                    true,
                    PriorityIdentifier.DEFAULT,
                    "a44aa7a9-463a-4e10-93dd-bde8de3215bc");
    private static final SmsMfaData BACKUP_PRIORITY_SMS =
            new SmsMfaData(
                    "0123456",
                    true,
                    true,
                    PriorityIdentifier.BACKUP,
                    "20fbea7e-4c4e-4a32-a7b5-000bb4863660");
    private String publicSubjectId;

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
        handler = new MFAMethodsDeleteHandler(mfaMethodEnabledConfigurationService);
        publicSubjectId = userStoreExtension.signUp(EMAIL, PASSWORD);
    }

    @Test
    void shouldReturn204AndDeleteAnMfaMethodWhenUserExists() {
        userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, DEFAULT_PRIORITY_AUTH_APP);
        userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, BACKUP_PRIORITY_SMS);
        userStoreExtension.setMfaMethodsMigrated(EMAIL, true);

        var response =
                makeRequest(
                        Optional.empty(),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of(
                                "publicSubjectId",
                                publicSubjectId,
                                "mfaIdentifier",
                                BACKUP_PRIORITY_SMS.mfaIdentifier()),
                        Collections.emptyMap());

        assertEquals(204, response.getStatusCode());

        var mfaMethods = userStoreExtension.getMfaMethod(EMAIL);
        assertEquals(1, mfaMethods.size());

        var mfaMethod = mfaMethods.stream().findFirst().get();

        assertEquals(MFAMethodType.AUTH_APP.getValue(), mfaMethod.getMfaMethodType());
        assertEquals(DEFAULT_PRIORITY_AUTH_APP.mfaIdentifier(), mfaMethod.getMfaIdentifier());
    }

    @Test
    void shouldReturn404WhenUserDoesNotExist() {
        var nonExistentPublicSubjectId = "userDoesNotExist";
        var response =
                makeRequest(
                        Optional.empty(),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of(
                                "publicSubjectId",
                                nonExistentPublicSubjectId,
                                "mfaIdentifier",
                                "mfaIdentifier"),
                        Collections.emptyMap());

        assertEquals(404, response.getStatusCode());
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1056));
    }

    @Test
    void shouldReturn404WhenMfaMethodDoesNotExist() {
        userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, DEFAULT_PRIORITY_AUTH_APP);
        userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, BACKUP_PRIORITY_SMS);
        userStoreExtension.setMfaMethodsMigrated(EMAIL, true);
        var response =
                makeRequest(
                        Optional.empty(),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of(
                                "publicSubjectId",
                                publicSubjectId,
                                "mfaIdentifier",
                                "some-other-identifier"),
                        Collections.emptyMap());

        assertEquals(404, response.getStatusCode());
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1065));

        assertEquals(2, userStoreExtension.getMfaMethod(EMAIL).size());
    }

    @Test
    void shouldReturn400WhenMfaMethodIsDefault() {
        userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, DEFAULT_PRIORITY_AUTH_APP);
        userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, BACKUP_PRIORITY_SMS);
        userStoreExtension.setMfaMethodsMigrated(EMAIL, true);
        var response =
                makeRequest(
                        Optional.empty(),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of(
                                "publicSubjectId",
                                publicSubjectId,
                                "mfaIdentifier",
                                DEFAULT_PRIORITY_AUTH_APP.mfaIdentifier()),
                        Collections.emptyMap());

        assertEquals(409, response.getStatusCode());
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1066));

        assertEquals(2, userStoreExtension.getMfaMethod(EMAIL).size());
    }

    @Test
    void shouldReturn400WhenUsersMfaMethodsAreNotMigrated() {
        userStoreExtension.setMfaMethodsMigrated(EMAIL, false);

        userStoreExtension.addMfaMethod(EMAIL, MFAMethodType.AUTH_APP, true, true, "credential");
        var response =
                makeRequest(
                        Optional.empty(),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of(
                                "publicSubjectId",
                                publicSubjectId,
                                "mfaIdentifier",
                                DEFAULT_PRIORITY_AUTH_APP.mfaIdentifier()),
                        Collections.emptyMap());

        assertEquals(400, response.getStatusCode());
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1067));

        assertEquals(1, userStoreExtension.getMfaMethod(EMAIL).size());
    }
}

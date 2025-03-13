package uk.gov.di.accountmanagement.api;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.accountmanagement.lambda.MFAMethodsDeleteHandler;
import uk.gov.di.authentication.shared.entity.AuthAppMfaData;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.MFAMethodType;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.SmsMfaData;
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
    }

    @Test
    void shouldReturn204AndDeleteAnMfaMethodWhenUserExists() {
        var publicSubjectId = userStoreExtension.signUp(EMAIL, PASSWORD);
        var defaultPriorityIdentifier = "a44aa7a9-463a-4e10-93dd-bde8de3215bc";
        var backupPriorityIdentifier = "20fbea7e-4c4e-4a32-a7b5-000bb4863660";
        userStoreExtension.addMfaMethodSupportingMultiple(
                EMAIL,
                new AuthAppMfaData(
                        "some-credential",
                        true,
                        true,
                        PriorityIdentifier.DEFAULT,
                        defaultPriorityIdentifier));
        userStoreExtension.addMfaMethodSupportingMultiple(
                EMAIL,
                new SmsMfaData(
                        "0123456",
                        true,
                        true,
                        PriorityIdentifier.BACKUP,
                        backupPriorityIdentifier));
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
                                backupPriorityIdentifier),
                        Collections.emptyMap());

        assertEquals(204, response.getStatusCode());

        var mfaMethods = userStoreExtension.getMfaMethod(EMAIL);
        assertEquals(1, mfaMethods.size());

        var mfaMethod = mfaMethods.stream().findFirst().get();

        assertEquals(MFAMethodType.AUTH_APP.getValue(), mfaMethod.getMfaMethodType());
        assertEquals(defaultPriorityIdentifier, mfaMethod.getMfaIdentifier());
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
}

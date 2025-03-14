package uk.gov.di.accountmanagement.api;

import com.google.gson.JsonParser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.accountmanagement.lambda.MFAMethodsCreateHandler;
import uk.gov.di.authentication.shared.entity.AuthAppMfaDetail;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.MFAMethod;
import uk.gov.di.authentication.shared.entity.MFAMethodType;
import uk.gov.di.authentication.shared.entity.MfaDetail;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.SmsMfaDetail;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;

class MFAMethodsCreateHandlerIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String TEST_EMAIL = "test@email.com";
    private static final String TEST_PASSWORD = "test-password";
    private static final String TEST_PHONE_NUMBER = "07123123123";
    private static final String TEST_CREDENTIAL = "ZZ11BB22CC33DD44EE55FF66GG77HH88II99JJ00";
    private static String TEST_PUBLIC_SUBJECT;

    @BeforeEach
    void setUp() {
        ConfigurationService mfaMethodEnabledConfigurationService =
                new ConfigurationService() {
                    @Override
                    public boolean isMfaMethodManagementApiEnabled() {
                        return true;
                    }
                };

        handler = new MFAMethodsCreateHandler(mfaMethodEnabledConfigurationService);
        userStore.signUp(TEST_EMAIL, TEST_PASSWORD);
        TEST_PUBLIC_SUBJECT =
                userStore.getUserProfileFromEmail(TEST_EMAIL).get().getPublicSubjectID();
    }

    @Test
    void shouldReturn200AndMfaMethodDataWhenAuthAppUserAddsSmsMfa() {
        userStore.addAuthAppMethod(TEST_EMAIL, true, true, TEST_CREDENTIAL);
        var response =
                makeRequest(
                        Optional.of(
                                constructRequestBody(
                                        PriorityIdentifier.BACKUP,
                                        new SmsMfaDetail(MFAMethodType.SMS, TEST_PHONE_NUMBER))),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of("publicSubjectId", TEST_PUBLIC_SUBJECT));
        assertEquals(200, response.getStatusCode());

        String extractedMfaIdentifier =
                JsonParser.parseString(response.getBody())
                        .getAsJsonObject()
                        .get("mfaIdentifier")
                        .getAsString();

        List<MFAMethod> mfaMethods = userStore.getMfaMethod(TEST_EMAIL);

        assertTrue(
                mfaMethods.stream()
                        .filter(
                                mfaMethod ->
                                        mfaMethod
                                                .getMfaMethodType()
                                                .equals(MFAMethodType.SMS.getValue()))
                        .filter(
                                mfaMethod ->
                                        mfaMethod.getMfaIdentifier().equals(extractedMfaIdentifier))
                        .filter(mfaMethod -> mfaMethod.getDestination().equals(TEST_PHONE_NUMBER))
                        .filter(
                                mfaMethod ->
                                        mfaMethod
                                                .getPriority()
                                                .equals(PriorityIdentifier.BACKUP.toString()))
                        .filter(MFAMethod::isMethodVerified)
                        .anyMatch(m -> true));
    }

    @Test
    void shouldReturn400AndBadRequestWhenPathParameterIsNotPresent() {
        var response =
                makeRequest(
                        Optional.of(
                                constructRequestBody(
                                        PriorityIdentifier.BACKUP,
                                        new SmsMfaDetail(MFAMethodType.SMS, TEST_PHONE_NUMBER))),
                        Collections.emptyMap(),
                        Collections.emptyMap());
        assertEquals(400, response.getStatusCode());
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1001));
    }

    @Test
    void shouldReturn400AndBadRequestWhenPublicSubjectIsNotInUserStore() {
        var response =
                makeRequest(
                        Optional.of(
                                constructRequestBody(
                                        PriorityIdentifier.BACKUP,
                                        new SmsMfaDetail(MFAMethodType.SMS, TEST_PHONE_NUMBER))),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of("publicSubjectId", "incorrect-public-subject-id"),
                        Collections.emptyMap());
        assertEquals(404, response.getStatusCode());
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1056));
    }

    private static String constructRequestBody(
            PriorityIdentifier priorityIdentifier, MfaDetail mfaDetail) {
        return format(
                """
                        {
                          "mfaMethod": {
                            "priorityIdentifier": "%s",
                            "method": %s
                          }
                        }
                        """,
                priorityIdentifier, constructMfaDetailJson(mfaDetail));
    }

    private static String constructExpectedResponse(
            String mfaIdentifier,
            PriorityIdentifier priorityIdentifier,
            boolean methodVerified,
            MfaDetail mfaDetail) {
        return format(
                """
                        {
                          "mfaIdentifier": "%s",
                          "priorityIdentifier": "%s",
                          "methodVerified": %s,
                          "method": %s
                        }
                        """,
                mfaIdentifier,
                priorityIdentifier,
                methodVerified,
                constructMfaDetailJson(mfaDetail));
    }

    private static String constructMfaDetailJson(MfaDetail mfaDetail) {
        if (mfaDetail instanceof SmsMfaDetail) {
            return format(
                    """
                            {
                              "mfaMethodType": "%s",
                              "phoneNumber": "%s"
                            }
                            """,
                    ((SmsMfaDetail) mfaDetail).mfaMethodType(),
                    ((SmsMfaDetail) mfaDetail).phoneNumber());
        } else {
            return format(
                    """
                            {
                              "mfaMethodType": "%s",
                              "credential": "%s"
                            }
                            """,
                    ((AuthAppMfaDetail) mfaDetail).mfaMethodType(),
                    ((AuthAppMfaDetail) mfaDetail).credential());
        }
    }
}

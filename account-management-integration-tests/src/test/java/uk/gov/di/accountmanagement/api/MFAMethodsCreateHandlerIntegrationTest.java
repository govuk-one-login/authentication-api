package uk.gov.di.accountmanagement.api;

import com.google.gson.JsonParser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.accountmanagement.lambda.MFAMethodsCreateHandler;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.MFAMethodType;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;

import java.util.Collections;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.authentication.shared.services.DynamoMfaMethodsService.HARDCODED_APP_MFA_ID;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;

class MFAMethodsCreateHandlerIntegrationTest extends ApiGatewayHandlerIntegrationTest {
    private static final String TEST_EMAIL = "test@email.com";
    private static final String TEST_PASSWORD = "test-password";
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
    void shouldReturn200AndMfaMethodData() {
        var response =
                makeRequest(
                        Optional.of(
                                format(
                                        """
                                        { "mfaMethod": {
                                            "priorityIdentifier": "BACKUP",
                                            "method": {
                                                "mfaMethodType": "%s",
                                                "credential": "%s" }
                                            }
                                        }
                                       """,
                                        MFAMethodType.AUTH_APP.getValue(), TEST_CREDENTIAL)),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of("publicSubjectId", TEST_PUBLIC_SUBJECT),
                        Collections.emptyMap());

        assertEquals(200, response.getStatusCode());
        var expectedResponse =
                format(
                        """
                {
                  "mfaIdentifier": "%s",
                  "priorityIdentifier": "BACKUP",
                  "methodVerified": true,
                  "method": {
                    "mfaMethodType": "AUTH_APP",
                    "credential": "%s"
                  }
                }
                """,
                        HARDCODED_APP_MFA_ID, TEST_CREDENTIAL);
        var expectedResponseParsedToString =
                JsonParser.parseString(expectedResponse).getAsJsonObject().toString();

        assertEquals(expectedResponseParsedToString, response.getBody());
    }

    @Test
    void shouldReturn400AndBadRequestWhenPathParameterIsNotPresent() {
        var response =
                makeRequest(
                        Optional.of(
                                format(
                                        """
                                        { "mfaMethod": {
                                            "priorityIdentifier": "BACKUP",
                                            "method": {
                                                "mfaMethodType": "%s",
                                                "credential": "%s" }
                                            }
                                        }
                                       """,
                                        MFAMethodType.AUTH_APP.getValue(), TEST_CREDENTIAL)),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Collections.emptyMap());

        assertEquals(400, response.getStatusCode());
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1001));
    }
}

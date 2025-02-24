package uk.gov.di.accountmanagement.api;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.accountmanagement.lambda.CreateBackupMFAMethod;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.MFAMethodType;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;

import java.util.Collections;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;

class CreateBackupMFAMethodIntegrationTest extends ApiGatewayHandlerIntegrationTest {
    private static final String TEST_EMAIL = "test@email.com";
    private static final String TEST_PASSWORD = "test-password";
    private static final String TEST_CREDENTIAL = "ZZ11BB22CC33DD44EE55FF66GG77HH88II99JJ00";
    private static String TEST_PUBLIC_SUBJECT;

    @BeforeEach
    void setUp() {
        userStore.signUp(TEST_EMAIL, TEST_PASSWORD);
        TEST_PUBLIC_SUBJECT =
                userStore.getUserProfileFromEmail(TEST_EMAIL).get().getPublicSubjectID();
        handler = new CreateBackupMFAMethod(TEST_CONFIGURATION_SERVICE);
    }

    @Test
    void shouldReturn200AndHelloWorld() {
        userStore.addMfaMethod(TEST_EMAIL, MFAMethodType.SMS, true, true, TEST_CREDENTIAL);

        var response =
                makeRequest(
                        Optional.of(
                                "{\n"
                                        + "\"mfaMethod\": {\n"
                                        + "\"priorityIdentifier\": \"BACKUP\",\n"
                                        + "\"method\": {\n"
                                        + "\"mfaMethodType\": \"AUTH_APP\",\n"
                                        + "\"credential\": \"AAAABBBBCCCCCDDDDD55551111EEEE2222FFFF3333GGGG4444\"\n"
                                        + "}\n"
                                        + "}\n"
                                        + "}"),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of("publicSubjectId", TEST_PUBLIC_SUBJECT),
                        Collections.emptyMap());

        assertEquals(200, response.getStatusCode());
        assertEquals(
                "{\n"
                        + "\"mfaMethod\": {\n"
                        + "\"priorityIdentifier\": \"BACKUP\",\n"
                        + "\"method\": {\n"
                        + "\"mfaMethodType\": \"AUTH_APP\",\n"
                        + "\"credential\": \"AAAABBBBCCCCCDDDDD55551111EEEE2222FFFF3333GGGG4444\"\n"
                        + "}\n"
                        + "}\n"
                        + "}",
                response.getBody());

        assertEquals(2, userStore.getMfaMethod(TEST_EMAIL).size());
    }

    @Test
    void shouldReturn400AndBadRequestWhenPathParameterIsWrong() {
        var response =
                makeRequest(
                        Optional.of(
                                "{\n"
                                        + "\"mfaMethod\": {\n"
                                        + "\"priorityIdentifier\": \"BACKUP\",\n"
                                        + "\"method\": {\n"
                                        + "\"mfaMethodType\": \"AUTH_APP\",\n"
                                        + "\"credential\": \"AAAABBBBCCCCCDDDDD55551111EEEE2222FFFF3333GGGG4444\"\n"
                                        + "}\n"
                                        + "}\n"
                                        + "}"),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of("publicSubjectId", "wrongPath"),
                        Collections.emptyMap());

        assertEquals(400, response.getStatusCode());
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1001));
    }
}

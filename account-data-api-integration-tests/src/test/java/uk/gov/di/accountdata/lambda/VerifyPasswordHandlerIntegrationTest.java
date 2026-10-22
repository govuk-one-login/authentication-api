package uk.gov.di.accountdata.lambda;

import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.accountdata.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.accountdata.entity.password.VerifyPasswordResponse;
import uk.gov.di.authentication.accountdata.lambda.VerifyPasswordHandler;
import uk.gov.di.authentication.accountdata.services.ConfigurationService;
import uk.gov.di.authentication.shared.entity.TermsAndConditions;
import uk.gov.di.authentication.shared.services.DynamoService;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.accountdata.basetest.APIGatewayProxyResponseEventMatcher.hasJsonBody;

class VerifyPasswordHandlerIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String PUBLIC_SUBJECT_ID_KEY = "publicSubjectId";
    private static final String TEST_EMAIL = "verify-password-test@example.com";
    private static final String TEST_PASSWORD = "password123";
    private static final Subject TEST_SUBJECT = new Subject();

    private final ConfigurationService configurationService = new ConfigurationService();
    private final DynamoService dynamoService = new DynamoService(configurationService);

    @BeforeEach
    void setUp() {
        handler = new VerifyPasswordHandler(configurationService);
    }

    @Test
    void shouldReturn200WhenPasswordVerificationSuccessful() {
        var user =
                dynamoService.signUp(
                        TEST_EMAIL,
                        TEST_PASSWORD,
                        TEST_SUBJECT,
                        new TermsAndConditions("1.0", "2024-01-01T00:00:00.000Z"));
        var userProfile = user.getUserProfile();
        var publicSubjectId = userProfile.getPublicSubjectID();

        var requestBody =
                """
                {
                    "password": "%s"
                }"""
                        .formatted(TEST_PASSWORD);

        var response =
                makeRequest(
                        Optional.of(requestBody),
                        new HashMap<String, String>(),
                        Collections.emptyMap(),
                        Map.of("publicSubjectId", publicSubjectId),
                        Map.of("principalId", publicSubjectId, "scope", "account-delete"));

        assertEquals(200, response.getStatusCode());
        assertThat(response, hasJsonBody(new VerifyPasswordResponse(true)));
    }

    @Test
    void shouldReturn404WhenUserNotFound() {
        var otherUserPublicSubjectId = "otherUserPublicSubjectId";

        var requestBody =
                """
                {
                    "password": "%s"
                }"""
                        .formatted(TEST_PASSWORD);

        var response =
                makeRequest(
                        Optional.of(requestBody),
                        new HashMap<String, String>(),
                        Collections.emptyMap(),
                        Map.of("publicSubjectId", otherUserPublicSubjectId),
                        Map.of("principalId", otherUserPublicSubjectId, "scope", "account-delete"));

        assertEquals(404, response.getStatusCode());
    }

    @Test
    void shouldReturn403WhenPublicSubjectIdMismatch() {
        var publicSubjectIdInParams = "publicSubjectIdInParams";
        var publicSubjectIdInAuthorizerParams = "publicSubjectIdInAuthorizerParams";

        var requestBody =
                """
                {
                    "password": "%s"
                }"""
                        .formatted(TEST_PASSWORD);

        var response =
                makeRequest(
                        Optional.of(requestBody),
                        new HashMap<String, String>(),
                        Collections.emptyMap(),
                        Map.of("publicSubjectId", publicSubjectIdInParams),
                        Map.of(
                                "principalId",
                                publicSubjectIdInAuthorizerParams,
                                "scope",
                                "account-delete"));

        assertEquals(403, response.getStatusCode());
    }
}

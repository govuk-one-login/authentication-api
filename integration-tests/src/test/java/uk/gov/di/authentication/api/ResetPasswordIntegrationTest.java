package uk.gov.di.authentication.api;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.frontendapi.entity.ResetPasswordWithCodeRequest;
import uk.gov.di.authentication.frontendapi.lambda.ResetPasswordHandler;
import uk.gov.di.authentication.shared.helpers.ObjectMapperFactory;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.NotifyStubExtension;
import uk.gov.di.authentication.sharedtest.helper.DynamoHelper;
import uk.gov.di.authentication.sharedtest.helper.RedisHelper;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class ResetPasswordIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String EMAIL_ADDRESS = "test@test.com";
    private static final String PASSWORD = "Pa55word";
    private static final String CODE = "0123456789";

    @RegisterExtension
    public static final NotifyStubExtension notifyStub =
            new NotifyStubExtension(8888, ObjectMapperFactory.getInstance());

    @BeforeEach
    public void setUp() {
        handler = new ResetPasswordHandler(configurationService);
        notifyStub.init();
    }

    @AfterEach
    public void resetStub() {
        notifyStub.reset();
    }

    @Test
    public void shouldUpdatePasswordAndReturn204() throws JsonProcessingException {
        String subject = "new-subject";
        ResetPasswordWithCodeRequest requestBody = new ResetPasswordWithCodeRequest(CODE, PASSWORD);
        DynamoHelper.signUp(EMAIL_ADDRESS, "password-1", new Subject(subject));
        RedisHelper.generateAndSavePasswordResetCode(subject, CODE, 900l);
        Map<String, String> headers = new HashMap<>();
        headers.put("X-API-Key", API_KEY);

        var response = makeRequest(Optional.of(requestBody), headers, Map.of());
        var notifyResponse = notifyStub.waitForRequest(60);

        assertThat(response, hasStatus(204));
        assertThat(notifyResponse.get("email_address").asText(), equalTo(EMAIL_ADDRESS));
    }
}

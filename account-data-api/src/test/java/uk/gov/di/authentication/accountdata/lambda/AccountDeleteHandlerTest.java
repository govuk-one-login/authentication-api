package uk.gov.di.authentication.accountdata.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.accountdata.services.AccountDeleteDynamoService;
import uk.gov.di.authentication.accountdata.services.ConfigurationService;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
import uk.gov.di.authentication.shared.services.DynamoService;

import java.net.URI;
import java.nio.ByteBuffer;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.accountdata.helpers.APIGatewayProxyResponseEventMatcher.hasStatus;
import static uk.gov.di.authentication.accountdata.helpers.RequestHelper.contextWithSourceIp;

class AccountDeleteHandlerTest {
    private static final String TEST_PUBLIC_SUBJECT = new Subject().getValue();
    private static final String TEST_INTERNAL_SUBJECT = new Subject().getValue();
    private static final String TEST_EMAIL = "test@test.com";
    private static final String PUBLIC_SUBJECT_ID_KEY = "publicSubjectId";
    private static final byte[] TEST_SALT = SaltHelper.generateNewSalt();
    private static final UserProfile TEST_USER_PROFILE =
            new UserProfile()
                    .withEmail(TEST_EMAIL)
                    .withPublicSubjectID(TEST_PUBLIC_SUBJECT)
                    .withSubjectID(TEST_INTERNAL_SUBJECT)
                    .withSalt(ByteBuffer.wrap(TEST_SALT));
    private static final String TEST_INTERNAL_SECTOR_URI = "https://test.account.gov.uk";
    private static final String TEST_INTERNAL_PAIRWISE_SUBJECT =
            ClientSubjectHelper.calculatePairwiseIdentifier(
                    TEST_INTERNAL_SUBJECT,
                    URI.create(TEST_INTERNAL_SECTOR_URI).getHost(),
                    TEST_SALT);
    private static final String IP_ADDRESS = "192.0.2.0/24";

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final DynamoService dynamoService = mock(DynamoService.class);
    private final AccountDeleteDynamoService accountDeleteDynamoService =
            mock(AccountDeleteDynamoService.class);

    private final Context context = mock(Context.class);
    private final AccountDeleteHandler handler =
            new AccountDeleteHandler(
                    configurationService, dynamoService, accountDeleteDynamoService);

    @Test
    void shouldReturn204AndCallAccountDelete() {
        when(dynamoService.getOptionalUserProfileFromPublicSubject(TEST_PUBLIC_SUBJECT))
                .thenReturn(Optional.of(TEST_USER_PROFILE));
        when(configurationService.getInternalSectorUri()).thenReturn(TEST_INTERNAL_SECTOR_URI);
        when(dynamoService.getOrGenerateSalt(TEST_USER_PROFILE)).thenReturn(TEST_SALT);

        var request = accountDeleteRequest(TEST_PUBLIC_SUBJECT, TEST_PUBLIC_SUBJECT);

        var result = handler.handleRequest(request, context);

        verify(accountDeleteDynamoService)
                .deleteAccount(TEST_EMAIL, TEST_INTERNAL_PAIRWISE_SUBJECT, TEST_PUBLIC_SUBJECT);
        assertThat(result, hasStatus(204));
    }

    @Test
    void shouldReturn404WhenUserProfileNotFoundForPublicSubject() {
        when(dynamoService.getOptionalUserProfileFromPublicSubject(TEST_PUBLIC_SUBJECT))
                .thenReturn(Optional.empty());

        var request = accountDeleteRequest(TEST_PUBLIC_SUBJECT, TEST_PUBLIC_SUBJECT);

        var result = handler.handleRequest(request, context);

        assertEquals(
                "{\"code\":1056,\"message\":\"User not found or no match\"}", result.getBody());
        assertThat(result, hasStatus(404));
    }

    private static Stream<Map<String, String>> invalidPathParameters() {
        return Stream.of(Map.of("publicSubjectId", ""), Map.of());
    }

    @ParameterizedTest
    @MethodSource("invalidPathParameters")
    void shouldReturn400IfPathParameterIsInvalid(Map<String, String> pathParameters) {
        var requestContext = contextWithSourceIp(IP_ADDRESS);
        requestContext.setAuthorizer(
                Map.of("principalId", "any-subject", "scope", "account-delete"));
        var request =
                new APIGatewayProxyRequestEvent()
                        .withRequestContext(requestContext)
                        .withPathParameters(pathParameters);

        var result = handler.handleRequest(request, context);

        assertEquals(
                "{\"code\":1001,\"message\":\"Request is missing parameters\"}", result.getBody());
        assertThat(result, hasStatus(400));
    }

    @Test
    void shouldReturn403WhenSubjectIdDoesNotMatchAuthorizer() {
        var request = accountDeleteRequest(TEST_PUBLIC_SUBJECT, "another-subject-id");

        var result = handler.handleRequest(request, context);

        assertEquals("{\"code\":4010,\"message\":\"Unauthorized request\"}", result.getBody());
        assertThat(result, hasStatus(403));
    }

    @Test
    void shouldReturn403WhenScopeDoesNotMatchEndpoint() {
        var requestContext = contextWithSourceIp(IP_ADDRESS);
        requestContext.setAuthorizer(
                Map.of("principalId", TEST_PUBLIC_SUBJECT, "scope", "passkey-delete"));
        var request =
                new APIGatewayProxyRequestEvent()
                        .withRequestContext(requestContext)
                        .withPathParameters(Map.of(PUBLIC_SUBJECT_ID_KEY, TEST_PUBLIC_SUBJECT));

        var result = handler.handleRequest(request, context);

        assertEquals("{\"code\":4010,\"message\":\"Unauthorized request\"}", result.getBody());
        assertThat(result, hasStatus(403));
    }

    @Test
    void shouldReturn500WhenDeleteAccountThrowsException() {
        when(dynamoService.getOptionalUserProfileFromPublicSubject(TEST_PUBLIC_SUBJECT))
                .thenReturn(Optional.of(TEST_USER_PROFILE));
        when(configurationService.getInternalSectorUri()).thenReturn(TEST_INTERNAL_SECTOR_URI);
        when(dynamoService.getOrGenerateSalt(TEST_USER_PROFILE)).thenReturn(TEST_SALT);
        doThrow(new RuntimeException("DynamoDB transaction failed"))
                .when(accountDeleteDynamoService)
                .deleteAccount(anyString(), anyString(), anyString());

        var request = accountDeleteRequest(TEST_PUBLIC_SUBJECT, TEST_PUBLIC_SUBJECT);

        var result = handler.handleRequest(request, context);

        assertEquals("{\"code\":5000,\"message\":\"Internal server error\"}", result.getBody());
        assertThat(result, hasStatus(500));
    }

    private APIGatewayProxyRequestEvent accountDeleteRequest(
            String publicSubjectId, String principalId) {
        var requestContext = contextWithSourceIp(IP_ADDRESS);
        requestContext.setAuthorizer(Map.of("principalId", principalId, "scope", "account-delete"));
        return new APIGatewayProxyRequestEvent()
                .withRequestContext(requestContext)
                .withPathParameters(Map.of(PUBLIC_SUBJECT_ID_KEY, publicSubjectId));
    }
}

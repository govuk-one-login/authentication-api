package uk.gov.di.accountmanagement.helpers;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.shared.domain.RequestHeaders;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.accountmanagement.helpers.AuditHelper.TXMA_ENCODED_HEADER_NAME;
import static uk.gov.di.authentication.shared.entity.AuthSessionItem.ATTRIBUTE_CLIENT_ID;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1071;
import static uk.gov.di.authentication.sharedtest.helper.RequestEventHelper.contextWithSourceIp;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;

class AuditHelperTest {

    @RegisterExtension
    public final CaptureLoggingExtension logging = new CaptureLoggingExtension(AuditHelper.class);

    private static final String TEST_INTERNAL_SECTOR_URI = "https://test.account.gov.uk";
    private static final String TEST_SESSION_ID = "some-session-id";
    private static final String TEST_IP_ADDRESS = "127.0.0.1";
    private static final String TEST_CLIENT_ID = "test-client-id";
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final DynamoService dynamoService = mock(DynamoService.class);
    private final UserProfile userProfile = new UserProfile().withSubjectID("subject");
    private static final byte[] TEST_SALT = SaltHelper.generateNewSalt();
    private final String pairwiseId =
            ClientSubjectHelper.calculatePairwiseIdentifier(
                    userProfile.getSubjectID(), URI.create(TEST_INTERNAL_SECTOR_URI), TEST_SALT);
    private APIGatewayProxyRequestEvent input;

    @Nested
    class TxmaAuditEncodedTests {
        @Test
        void shouldRetrieveATxmaAuditEncodedFieldFromAHeader() {
            String auditValue = "validHeaderValue";
            var result =
                    AuditHelper.getTxmaAuditEncoded(Map.of(TXMA_ENCODED_HEADER_NAME, auditValue));
            assertEquals(Optional.of(auditValue), result);
        }

        @Test
        void shouldLogAwarningWhenMissingHeader() {
            var result = AuditHelper.getTxmaAuditEncoded(Map.of());
            assertEquals(Optional.empty(), result);
            assertThat(
                    logging.events(),
                    hasItem(withMessageContaining("Audit header field value cannot be empty")));
        }

        @Test
        void shouldLogAWarningWhenEmptyHeader() {
            var result = AuditHelper.getTxmaAuditEncoded(Map.of(TXMA_ENCODED_HEADER_NAME, ""));
            assertEquals(Optional.empty(), result);
            assertThat(
                    logging.events(),
                    hasItem(withMessageContaining("Audit header field value cannot be empty")));
        }
    }

    @Nested
    class BuildAuditContextTests {
        @Test
        void shouldBuildAuditContextSuccessfully() {
            when(configurationService.getInternalSectorUri()).thenReturn(TEST_INTERNAL_SECTOR_URI);

            input = new APIGatewayProxyRequestEvent();

            Map<String, String> headers = new HashMap<>(CommonTestVariables.VALID_HEADERS);
            headers.put(RequestHeaders.SESSION_ID_HEADER, TEST_SESSION_ID);
            input.setHeaders(headers);
            input.setRequestContext(contextWithSourceIp(TEST_IP_ADDRESS));
            input.getRequestContext().setAuthorizer(Map.of(ATTRIBUTE_CLIENT_ID, TEST_CLIENT_ID));

            when(configurationService.getInternalSectorUri())
                    .thenReturn("https://test.account.gov.uk");
            when(dynamoService.getOrGenerateSalt(userProfile)).thenReturn(TEST_SALT);

            Result<ErrorResponse, AuditContext> result =
                    AuditHelper.buildAuditContext(
                            configurationService, dynamoService, input, userProfile);

            assertTrue(result.isSuccess());
            AuditContext context = result.getSuccess();
            assertEquals("test-client-id", context.clientId());
            assertEquals(CommonTestVariables.SESSION_ID, context.sessionId());
            assertEquals(pairwiseId, context.subjectId());
            assertEquals(TEST_IP_ADDRESS, context.ipAddress());
            assertEquals(
                    Optional.of(CommonTestVariables.TXMA_ENCODED_HEADER_VALUE),
                    context.txmaAuditEncoded());
        }

        @Test
        void shouldReturnErrorWhenExceptionOccurs() {
            when(configurationService.getInternalSectorUri())
                    .thenThrow(new RuntimeException("Test exception"));

            input = new APIGatewayProxyRequestEvent();

            Result<ErrorResponse, AuditContext> result =
                    AuditHelper.buildAuditContext(
                            configurationService, dynamoService, input, userProfile);

            assertTrue(result.isFailure());
            assertEquals(ERROR_1071, result.getFailure());
            assertThat(
                    logging.events(),
                    hasItem(withMessageContaining("Error building audit context")));
        }
    }
}

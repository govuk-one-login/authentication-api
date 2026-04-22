package uk.gov.di.accountmanagement.helpers;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.shared.domain.RequestHeaders;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.mfa.request.MfaMethodCreateRequest;
import uk.gov.di.authentication.shared.entity.mfa.request.RequestAuthAppMfaDetail;
import uk.gov.di.authentication.shared.entity.mfa.request.RequestSmsMfaDetail;
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
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_ACCOUNT_RECOVERY;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_JOURNEY_TYPE;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_MFA_CODE_ENTERED;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_MFA_METHOD;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_MFA_TYPE;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_NOTIFICATION_TYPE;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_PHONE_NUMBER_COUNTRY_CODE;
import static uk.gov.di.authentication.shared.entity.AuthSessionItem.ATTRIBUTE_CLIENT_ID;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.UNEXPECTED_ACCT_MGMT_ERROR;
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
            assertEquals(UNEXPECTED_ACCT_MGMT_ERROR, result.getFailure());
            assertThat(
                    logging.events(),
                    hasItem(withMessageContaining("Error building audit context")));
        }
    }

    @Nested
    class EnrichAuditContextForMfaMethodTests {

        private final AuditContext baseContext = AuditContext.emptyAuditContext();

        @Test
        void shouldReturnUnmodifiedContextWhenRequestIsNull() {
            var result =
                    AuditHelper.enrichAuditContextForMfaMethod(
                            AccountManagementAuditableEvent.AUTH_MFA_METHOD_ADD_COMPLETED,
                            baseContext,
                            null);

            assertEquals(baseContext, result);
        }

        @Test
        void shouldAddMfaTypeAndMethodForAuthAppRequest() {
            var request =
                    MfaMethodCreateRequest.from(
                            PriorityIdentifier.BACKUP,
                            new RequestAuthAppMfaDetail("some-credential"));

            var result =
                    AuditHelper.enrichAuditContextForMfaMethod(
                            AccountManagementAuditableEvent.AUTH_MFA_METHOD_ADD_COMPLETED,
                            baseContext,
                            request);

            assertEquals(
                    "AUTH_APP",
                    result.getMetadataItemByKey(AUDIT_EVENT_EXTENSIONS_MFA_TYPE).get().value());
            assertEquals(
                    "backup",
                    result.getMetadataItemByKey(AUDIT_EVENT_EXTENSIONS_MFA_METHOD).get().value());
            assertTrue(
                    result.getMetadataItemByKey(AUDIT_EVENT_EXTENSIONS_PHONE_NUMBER_COUNTRY_CODE)
                            .isEmpty());
        }

        @Test
        void shouldAddPhoneNumberAndCountryCodeForSmsRequest() {
            var request =
                    MfaMethodCreateRequest.from(
                            PriorityIdentifier.BACKUP,
                            new RequestSmsMfaDetail("+447700900000", "123456"));

            var result =
                    AuditHelper.enrichAuditContextForMfaMethod(
                            AccountManagementAuditableEvent.AUTH_MFA_METHOD_ADD_COMPLETED,
                            baseContext,
                            request);

            assertEquals("+447700900000", result.phoneNumber());
            assertTrue(
                    result.getMetadataItemByKey(AUDIT_EVENT_EXTENSIONS_PHONE_NUMBER_COUNTRY_CODE)
                            .isPresent());
        }

        @Test
        void shouldAddOtpAndNotificationTypeForSmsCodeVerified() {
            var request =
                    MfaMethodCreateRequest.from(
                            PriorityIdentifier.BACKUP,
                            new RequestSmsMfaDetail("+447700900000", "123456"));

            var result =
                    AuditHelper.enrichAuditContextForMfaMethod(
                            AccountManagementAuditableEvent.AUTH_CODE_VERIFIED,
                            baseContext,
                            request);

            assertEquals(
                    "123456",
                    result.getMetadataItemByKey(AUDIT_EVENT_EXTENSIONS_MFA_CODE_ENTERED)
                            .get()
                            .value());
            assertEquals(
                    "MFA_SMS",
                    result.getMetadataItemByKey(AUDIT_EVENT_EXTENSIONS_NOTIFICATION_TYPE)
                            .get()
                            .value());
        }

        @Test
        void shouldNotAddOtpFieldsWhenOtpIsNull() {
            var request =
                    MfaMethodCreateRequest.from(
                            PriorityIdentifier.BACKUP,
                            new RequestSmsMfaDetail("+447700900000", null));

            var result =
                    AuditHelper.enrichAuditContextForMfaMethod(
                            AccountManagementAuditableEvent.AUTH_CODE_VERIFIED,
                            baseContext,
                            request);

            assertTrue(
                    result.getMetadataItemByKey(AUDIT_EVENT_EXTENSIONS_MFA_CODE_ENTERED).isEmpty());
        }

        @Test
        void shouldAddAccountRecoveryAndJourneyTypeForCodeVerified() {
            var request =
                    MfaMethodCreateRequest.from(
                            PriorityIdentifier.BACKUP,
                            new RequestAuthAppMfaDetail("some-credential"));

            var result =
                    AuditHelper.enrichAuditContextForMfaMethod(
                            AccountManagementAuditableEvent.AUTH_CODE_VERIFIED,
                            baseContext,
                            request);

            assertEquals(
                    "false",
                    result.getMetadataItemByKey(AUDIT_EVENT_EXTENSIONS_ACCOUNT_RECOVERY)
                            .get()
                            .value());
            assertEquals(
                    "ACCOUNT_MANAGEMENT",
                    result.getMetadataItemByKey(AUDIT_EVENT_EXTENSIONS_JOURNEY_TYPE).get().value());
        }

        @Test
        void shouldFormatPhoneNumberToE164ForAuditContext() {
            var request =
                    MfaMethodCreateRequest.from(
                            PriorityIdentifier.BACKUP,
                            new RequestSmsMfaDetail("07700900000", "123456"));

            var result =
                    AuditHelper.enrichAuditContextForMfaMethod(
                            AccountManagementAuditableEvent.AUTH_MFA_METHOD_ADD_COMPLETED,
                            baseContext,
                            request);

            assertEquals("+447700900000", result.phoneNumber());
        }

        @Test
        void shouldNotAddAccountRecoveryFieldsForNonCodeVerifiedEvent() {
            var request =
                    MfaMethodCreateRequest.from(
                            PriorityIdentifier.BACKUP,
                            new RequestAuthAppMfaDetail("some-credential"));

            var result =
                    AuditHelper.enrichAuditContextForMfaMethod(
                            AccountManagementAuditableEvent.AUTH_MFA_METHOD_ADD_COMPLETED,
                            baseContext,
                            request);

            assertTrue(
                    result.getMetadataItemByKey(AUDIT_EVENT_EXTENSIONS_ACCOUNT_RECOVERY).isEmpty());
            assertTrue(result.getMetadataItemByKey(AUDIT_EVENT_EXTENSIONS_JOURNEY_TYPE).isEmpty());
        }
    }
}

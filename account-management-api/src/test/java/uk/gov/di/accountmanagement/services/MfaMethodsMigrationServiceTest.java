package uk.gov.di.accountmanagement.services;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import uk.gov.di.accountmanagement.helpers.AuditHelper;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.entity.mfa.MfaDetail;
import uk.gov.di.authentication.shared.entity.mfa.request.RequestAuthAppMfaDetail;
import uk.gov.di.authentication.shared.entity.mfa.request.RequestSmsMfaDetail;
import uk.gov.di.authentication.shared.helpers.ClientSessionIdHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.mfa.MFAMethodsService;
import uk.gov.di.authentication.shared.services.mfa.MfaMigrationFailureReason;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent.AUTH_MFA_METHOD_MIGRATION_ATTEMPTED;
import static uk.gov.di.accountmanagement.helpers.CommonTestVariables.PERSISTENT_ID;
import static uk.gov.di.accountmanagement.helpers.CommonTestVariables.SESSION_ID;
import static uk.gov.di.accountmanagement.helpers.CommonTestVariables.TXMA_ENCODED_HEADER_VALUE;
import static uk.gov.di.authentication.shared.services.mfa.MfaMigrationFailureReason.ALREADY_MIGRATED;
import static uk.gov.di.authentication.shared.services.mfa.MfaMigrationFailureReason.NO_CREDENTIALS_FOUND_FOR_USER;
import static uk.gov.di.authentication.shared.services.mfa.MfaMigrationFailureReason.UNEXPECTED_ERROR_RETRIEVING_METHODS;
import static uk.gov.di.authentication.sharedtest.helper.RequestEventHelper.identityWithSourceIp;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;

class MfaMethodsMigrationServiceTest {
    private final MFAMethodsService mfaMethodsService = mock(MFAMethodsService.class);
    private final AuditContext auditContext = mock(AuditContext.class);
    private final AuditService auditService = mock(AuditService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);

    private static final String TEST_PHONE_NUMBER = "07123123123";
    private static final String TEST_NON_CLIENT_SESSION_ID = "some-non-client-session-id";
    private static final String EMAIL = "email@example.com";
    private static final String TEST_PUBLIC_SUBJECT = new Subject().getValue();
    private static final String TEST_CLIENT = "test-client";
    private static final String MFA_IDENTIFIER = "some-mfa-identifier";

    @RegisterExtension
    public final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(MfaMethodsMigrationService.class);

    private final Logger logger = LogManager.getLogger(MfaMethodsMigrationService.class);

    private static final String MIGRATION_SUCCESS_LOG = "MFA Methods migrated for user";

    private MfaMethodsMigrationService service;

    @BeforeEach
    void setUp() {
        service =
                new MfaMethodsMigrationService(
                        configurationService, mfaMethodsService, auditService);
    }

    @AfterEach
    void tearDown() {
        reset(mfaMethodsService);
        reset(auditContext);
        reset(configurationService);
        reset(auditService);
    }

    @Nested
    class MigrationLogic {
        @Test
        void shouldReturnAnEmptyAndLogWhenUserNotMigratedAndMigrationReturnsNoError() {
            var userProfile = new UserProfile().withMfaMethodsMigrated(false).withEmail(EMAIL);
            var input = generateApiGatewayEvent();
            var mfaDetail = new RequestSmsMfaDetail(TEST_PHONE_NUMBER, "123123");

            when(mfaMethodsService.migrateMfaCredentialsForUser(userProfile))
                    .thenReturn(Result.success(false));

            var result =
                    service.migrateMfaCredentialsForUserIfRequired(
                            userProfile, logger, input, mfaDetail);

            assertEquals(Optional.empty(), result);

            assertThat(logging.events(), hasItem(withMessageContaining(MIGRATION_SUCCESS_LOG)));
        }

        @Test
        void shouldReturnAnEmptyAndNotLogSuccessWhenUserAlreadyMigrated() {
            var userProfile = new UserProfile().withMfaMethodsMigrated(true).withEmail(EMAIL);
            var input = generateApiGatewayEvent();
            var mfaDetail = new RequestSmsMfaDetail(TEST_PHONE_NUMBER, "123123");

            var result =
                    service.migrateMfaCredentialsForUserIfRequired(
                            userProfile, logger, input, mfaDetail);

            assertEquals(Optional.empty(), result);

            assertThat(
                    logging.events(), not(hasItem(withMessageContaining(MIGRATION_SUCCESS_LOG))));
        }

        private static Stream<Arguments> fatalMigrationErrorsToHttpStatusAndError() {
            return Stream.of(
                    Arguments.of(NO_CREDENTIALS_FOUND_FOR_USER, 404, ErrorResponse.ERROR_1056),
                    Arguments.of(
                            UNEXPECTED_ERROR_RETRIEVING_METHODS, 500, ErrorResponse.ERROR_1064));
        }

        @ParameterizedTest
        @MethodSource("fatalMigrationErrorsToHttpStatusAndError")
        void shouldReturnAppropriateApiProxyResponseWhenMigrationReturnsError(
                MfaMigrationFailureReason migrationFailureReason,
                int expectedHttpStatus,
                ErrorResponse expectedErrorResponse) {
            var userProfile = new UserProfile().withMfaMethodsMigrated(false).withEmail(EMAIL);
            var input = generateApiGatewayEvent();
            var mfaDetail = new RequestSmsMfaDetail(TEST_PHONE_NUMBER, "123123");

            when(mfaMethodsService.migrateMfaCredentialsForUser(userProfile))
                    .thenReturn(Result.failure(migrationFailureReason));

            var maybeErrorResponse =
                    service.migrateMfaCredentialsForUserIfRequired(
                            userProfile, logger, input, mfaDetail);

            assertTrue(maybeErrorResponse.isPresent());
            assertEquals(expectedHttpStatus, maybeErrorResponse.get().getStatusCode());
            assertThat(maybeErrorResponse.get(), hasJsonBody(expectedErrorResponse));

            assertThat(
                    logging.events(), not(hasItem(withMessageContaining(MIGRATION_SUCCESS_LOG))));

            assertThat(
                    logging.events(),
                    hasItem(
                            withMessageContaining(
                                    format(
                                            "Failed to migrate user's MFA credentials due to %s",
                                            migrationFailureReason))));
        }

        @Test
        void shouldNotReturnFailureIfMigrationFailsDueToMethodsAlreadyMigrated() {
            var userProfile = new UserProfile().withEmail(EMAIL).withMfaMethodsMigrated(false);
            var input = generateApiGatewayEvent();
            var mfaDetail = new RequestSmsMfaDetail(TEST_PHONE_NUMBER, "123123");

            when(mfaMethodsService.migrateMfaCredentialsForUser(userProfile))
                    .thenReturn(Result.failure(ALREADY_MIGRATED));

            var maybeErrorResponse =
                    service.migrateMfaCredentialsForUserIfRequired(
                            userProfile, logger, input, mfaDetail);

            assertEquals(Optional.empty(), maybeErrorResponse);

            assertThat(
                    logging.events(), not(hasItem(withMessageContaining(MIGRATION_SUCCESS_LOG))));

            assertThat(
                    logging.events(),
                    hasItem(
                            withMessageContaining(
                                    "Failed to migrate user's MFA credentials due to ALREADY_MIGRATED")));
        }
    }

    @Nested
    class AuditEvent {

        private static Stream<Arguments> auditEventsExpectedResponsesForMfaTypes() {
            return Stream.of(
                    Arguments.of(
                            new RequestSmsMfaDetail(TEST_PHONE_NUMBER, "123123"),
                            MFAMethodType.SMS),
                    Arguments.of(
                            new RequestAuthAppMfaDetail(MFAMethodType.AUTH_APP, "123123"),
                            MFAMethodType.AUTH_APP));
        }

        @ParameterizedTest
        @MethodSource("auditEventsExpectedResponsesForMfaTypes")
        void shouldEmitAuditEventWhenMigrationSuccessful(
                MfaDetail mfaDetail, MFAMethodType expectedMfaMethodType) {
            // Given
            var userProfile = new UserProfile().withEmail(EMAIL).withMfaMethodsMigrated(false);
            var input = generateApiGatewayEvent();

            // Setup mock to return success
            when(mfaMethodsService.migrateMfaCredentialsForUser(userProfile))
                    .thenReturn(Result.success(true));

            // When
            service.migrateMfaCredentialsForUserIfRequired(userProfile, logger, input, mfaDetail);

            // Then
            ArgumentCaptor<AuditContext> auditContextCaptor =
                    ArgumentCaptor.forClass(AuditContext.class);
            verify(auditService)
                    .submitAuditEvent(
                            eq(AUTH_MFA_METHOD_MIGRATION_ATTEMPTED), auditContextCaptor.capture());

            AuditContext capturedContext = auditContextCaptor.getValue();

            containsMetadataPair(
                    capturedContext, "journey-type", JourneyType.ACCOUNT_MANAGEMENT.name());
            containsMetadataPair(capturedContext, "mfa-type", expectedMfaMethodType.getValue());
            containsMetadataPair(capturedContext, "migration-succeeded", "true");
            if (expectedMfaMethodType.equals(MFAMethodType.SMS)) {
                containsMetadataPair(capturedContext, "phone_number_country_code", "44");
            }
            assertEquals(EMAIL, capturedContext.email());
            assertEquals(TEST_CLIENT, capturedContext.clientSessionId());
            assertEquals("123.123.123.123", capturedContext.ipAddress());
            assertEquals(PERSISTENT_ID, capturedContext.persistentSessionId());
            assertEquals(userProfile.getPhoneNumber(), capturedContext.phoneNumber());
            assertEquals(SESSION_ID, capturedContext.sessionId());
            assertEquals(TEST_PUBLIC_SUBJECT, capturedContext.subjectId());
        }

        @ParameterizedTest
        @MethodSource("auditEventsExpectedResponsesForMfaTypes")
        void shouldEmitAuditEventWhenMigrationFails(
                MfaDetail mfaDetail, MFAMethodType expectedMfaMethodType) {
            // Given
            var userProfile = new UserProfile().withEmail(EMAIL).withMfaMethodsMigrated(false);
            var input = generateApiGatewayEvent();
            when(mfaMethodsService.migrateMfaCredentialsForUser(userProfile))
                    .thenReturn(Result.failure(ALREADY_MIGRATED));

            // When
            service.migrateMfaCredentialsForUserIfRequired(userProfile, logger, input, mfaDetail);

            // Then
            ArgumentCaptor<AuditContext> auditContextCaptor =
                    ArgumentCaptor.forClass(AuditContext.class);
            verify(auditService)
                    .submitAuditEvent(
                            eq(AUTH_MFA_METHOD_MIGRATION_ATTEMPTED), auditContextCaptor.capture());

            AuditContext capturedContext = auditContextCaptor.getValue();

            containsMetadataPair(
                    capturedContext, "journey-type", JourneyType.ACCOUNT_MANAGEMENT.name());
            containsMetadataPair(capturedContext, "mfa-type", expectedMfaMethodType.getValue());
            containsMetadataPair(capturedContext, "migration-succeeded", "false");
            if (expectedMfaMethodType.equals(MFAMethodType.SMS)) {
                containsMetadataPair(capturedContext, "phone_number_country_code", "44");
            }
            assertEquals(EMAIL, capturedContext.email());
            assertEquals(TEST_CLIENT, capturedContext.clientSessionId());
            assertEquals("123.123.123.123", capturedContext.ipAddress());
            assertEquals(PERSISTENT_ID, capturedContext.persistentSessionId());
            assertEquals(userProfile.getPhoneNumber(), capturedContext.phoneNumber());
            assertEquals(SESSION_ID, capturedContext.sessionId());
            assertEquals(TEST_PUBLIC_SUBJECT, capturedContext.subjectId());
        }
    }

    private APIGatewayProxyRequestEvent generateApiGatewayEvent() {
        APIGatewayProxyRequestEvent.ProxyRequestContext proxyRequestContext =
                new APIGatewayProxyRequestEvent.ProxyRequestContext();
        Map<String, Object> authorizerParams = new HashMap<>();
        authorizerParams.put("clientId", TEST_CLIENT);
        proxyRequestContext.setAuthorizer(authorizerParams);
        proxyRequestContext.setIdentity(identityWithSourceIp("123.123.123.123"));
        Map<String, String> headers =
                Map.of(
                        PersistentIdHelper.PERSISTENT_ID_HEADER_NAME,
                        PERSISTENT_ID,
                        "Session-Id",
                        SESSION_ID,
                        ClientSessionIdHelper.SESSION_ID_HEADER_NAME,
                        TEST_CLIENT,
                        AuditHelper.TXMA_ENCODED_HEADER_NAME,
                        TXMA_ENCODED_HEADER_VALUE);

        return new APIGatewayProxyRequestEvent()
                .withPathParameters(
                        Map.ofEntries(
                                Map.entry("publicSubjectId", TEST_PUBLIC_SUBJECT),
                                Map.entry("mfaIdentifier", MFA_IDENTIFIER)))
                .withHeaders(headers)
                .withRequestContext(proxyRequestContext);
    }

    private void containsMetadataPair(AuditContext capturedObject, String field, String value) {
        capturedObject
                .getMetadataItemByKey(field)
                .ifPresent(
                        actualMetadataPairForMfaMethod -> {
                            assertEquals(field, actualMetadataPairForMfaMethod.key());
                            assertEquals(value, actualMetadataPairForMfaMethod.value().toString());
                        });
    }
}

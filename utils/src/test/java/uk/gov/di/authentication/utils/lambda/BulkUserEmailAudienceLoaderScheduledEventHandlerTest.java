package uk.gov.di.authentication.utils.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.ScheduledEvent;
import net.minidev.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import uk.gov.di.authentication.shared.entity.BulkEmailStatus;
import uk.gov.di.authentication.shared.services.BulkEmailUsersService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.LambdaInvokerService;
import uk.gov.di.authentication.utils.domain.BulkEmailType;
import uk.gov.di.authentication.utils.domain.DynamoTable;
import uk.gov.di.authentication.utils.entity.BulkUserEmailAudienceUser;
import uk.gov.di.authentication.utils.exceptions.IncludedTermsAndConditionsConfigMissingException;
import uk.gov.di.authentication.utils.services.audienceloader.BulkEmailAudienceLoader;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.utils.lambda.BulkUserEmailAudienceLoaderScheduledEventHandler.GLOBAL_USERS_ADDED_COUNT;
import static uk.gov.di.authentication.utils.lambda.BulkUserEmailAudienceLoaderScheduledEventHandler.LAST_EVALUATED_KEY;
import static uk.gov.di.authentication.utils.lambda.BulkUserEmailAudienceLoaderScheduledEventHandler.TABLE_TO_SCAN;

class BulkUserEmailAudienceLoaderScheduledEventHandlerTest {

    private BulkUserEmailAudienceLoaderScheduledEventHandler
            bulkUserEmailAudienceLoaderScheduledEventHandler;

    private final Context mockContext = mock(Context.class);

    private final BulkEmailUsersService bulkEmailUsersService = mock(BulkEmailUsersService.class);

    private final ConfigurationService configurationService = mock(ConfigurationService.class);

    private final LambdaInvokerService lambdaInvokerService = mock(LambdaInvokerService.class);

    private final BulkEmailAudienceLoader audienceLoader = mock(BulkEmailAudienceLoader.class);

    private final ScheduledEvent scheduledEvent = mock(ScheduledEvent.class);

    private final String SUBJECT_ID = "subject-id";

    private final String[] TEST_SUBJECT_IDS = {
        "subject-id-1", "subject-id-2", "subject-id-3", "subject-id-4", "subject-id-5",
    };

    private final String functionName = "BULK_USER_EMAIL_AUDIENCE_LOADER";

    @BeforeEach
    void setUp() {
        bulkUserEmailAudienceLoaderScheduledEventHandler =
                new BulkUserEmailAudienceLoaderScheduledEventHandler(
                        bulkEmailUsersService,
                        configurationService,
                        lambdaInvokerService,
                        audienceLoader);
        when(configurationService.getBulkEmailLoaderLambdaName()).thenReturn(functionName);
        when(configurationService.getBulkUserEmailType())
                .thenReturn(BulkEmailType.TERMS_AND_CONDITIONS_BULK_EMAIL.name());
    }

    @Test
    void shouldAddOneBulkEmailUser() {
        when(configurationService.getBulkUserEmailMaxAudienceLoadUserCount()).thenReturn(100L);
        when(configurationService.getBulkUserEmailAudienceLoadUserBatchSize()).thenReturn(10L);
        when(audienceLoader.loadUsers(null, DynamoTable.USER_PROFILE))
                .thenReturn(testUserProfilesFromSubjectIds(List.of(SUBJECT_ID)));

        bulkUserEmailAudienceLoaderScheduledEventHandler.handleRequest(scheduledEvent, mockContext);

        verify(audienceLoader).validateConfig();
        verify(bulkEmailUsersService).addUser(SUBJECT_ID, BulkEmailStatus.PENDING);
    }

    @Test
    void shouldNotAddBulkEmailUserWhenMaxLoadAudienceUserCountIsZero() {
        when(configurationService.getBulkUserEmailMaxAudienceLoadUserCount()).thenReturn(0L);
        when(configurationService.getBulkUserEmailAudienceLoadUserBatchSize()).thenReturn(10L);
        when(audienceLoader.loadUsers(null, DynamoTable.USER_PROFILE))
                .thenReturn(testUserProfilesFromSubjectIds(List.of(SUBJECT_ID)));

        bulkUserEmailAudienceLoaderScheduledEventHandler.handleRequest(scheduledEvent, mockContext);

        verify(bulkEmailUsersService, never()).addUser(SUBJECT_ID, BulkEmailStatus.PENDING);
    }

    @Test
    void shouldAddManyBulkEmailUsers() {
        when(configurationService.getBulkUserEmailMaxAudienceLoadUserCount()).thenReturn(100L);
        when(configurationService.getBulkUserEmailAudienceLoadUserBatchSize()).thenReturn(10L);
        when(audienceLoader.loadUsers(null, DynamoTable.USER_PROFILE))
                .thenReturn(testUserProfilesFromSubjectIds(List.of(TEST_SUBJECT_IDS)));

        bulkUserEmailAudienceLoaderScheduledEventHandler.handleRequest(scheduledEvent, mockContext);

        List.of(TEST_SUBJECT_IDS)
                .forEach(
                        id ->
                                verify(bulkEmailUsersService, times(1))
                                        .addUser(id, BulkEmailStatus.PENDING));
    }

    @Test
    void shouldAddOnlyMaxLoadAudienceUserCountBulkEmailUsers() {
        when(configurationService.getBulkUserEmailMaxAudienceLoadUserCount()).thenReturn(100L);
        when(configurationService.getBulkUserEmailAudienceLoadUserBatchSize()).thenReturn(3L);
        when(audienceLoader.loadUsers(null, DynamoTable.USER_PROFILE))
                .thenReturn(testUserProfilesFromSubjectIds(List.of(TEST_SUBJECT_IDS)));

        bulkUserEmailAudienceLoaderScheduledEventHandler.handleRequest(scheduledEvent, mockContext);

        verify(bulkEmailUsersService, times(3)).addUser(any(), eq(BulkEmailStatus.PENDING));
    }

    @Test
    void shouldReinvokeLambdaWithLastSubjectIdAndIncrementedCountWhenNoInitialStartKey() {
        when(configurationService.getBulkUserEmailMaxAudienceLoadUserCount()).thenReturn(100L);
        when(configurationService.getBulkUserEmailAudienceLoadUserBatchSize()).thenReturn(10L);

        var subjectIds = List.of(TEST_SUBJECT_IDS[0], TEST_SUBJECT_IDS[1], TEST_SUBJECT_IDS[2]);
        var userProfiles = testUserProfilesFromSubjectIds(subjectIds);
        when(audienceLoader.loadUsers(null, DynamoTable.USER_PROFILE)).thenReturn(userProfiles);

        var event = new ScheduledEvent().withDetail(Map.of());

        bulkUserEmailAudienceLoaderScheduledEventHandler.handleRequest(event, mockContext);

        subjectIds.forEach(
                subjectId ->
                        verify(bulkEmailUsersService, times(1))
                                .addUser(subjectId, BulkEmailStatus.PENDING));

        List.of(TEST_SUBJECT_IDS[3], TEST_SUBJECT_IDS[4])
                .forEach(
                        otherSubjectId ->
                                verify(bulkEmailUsersService, never())
                                        .addUser(otherSubjectId, BulkEmailStatus.PENDING));

        var expectedLastEvaluatedEmail = emailFromSubjectId(TEST_SUBJECT_IDS[2]);
        assertEquals(
                Map.of(
                        LAST_EVALUATED_KEY,
                        expectedLastEvaluatedEmail,
                        GLOBAL_USERS_ADDED_COUNT,
                        Integer.toUnsignedLong(subjectIds.size()),
                        TABLE_TO_SCAN,
                        DynamoTable.USER_PROFILE),
                event.getDetail());
        JSONObject detail =
                new JSONObject()
                        .appendField(LAST_EVALUATED_KEY, expectedLastEvaluatedEmail)
                        .appendField(
                                GLOBAL_USERS_ADDED_COUNT, Integer.toUnsignedLong(subjectIds.size()))
                        .appendField(TABLE_TO_SCAN, DynamoTable.USER_PROFILE);
        String payloadString = new JSONObject().appendField("detail", detail).toJSONString();

        verify(lambdaInvokerService, times(1)).invokeAsyncWithPayload(payloadString, functionName);
    }

    @Test
    void shouldReinvokeLambdaWithLastSubjectIdWithInitialStartKeyAndCount() {
        when(configurationService.getBulkUserEmailMaxAudienceLoadUserCount()).thenReturn(100L);
        when(configurationService.getBulkUserEmailAudienceLoadUserBatchSize()).thenReturn(10L);

        var lastEvaluatedEmail = emailFromSubjectId(TEST_SUBJECT_IDS[2]);
        var lastEvaluatedKey =
                Map.of("Email", AttributeValue.builder().s(lastEvaluatedEmail).build());
        var tableToScan = DynamoTable.USER_PROFILE;

        var event =
                new ScheduledEvent()
                        .withDetail(
                                Map.of(
                                        LAST_EVALUATED_KEY,
                                        lastEvaluatedEmail,
                                        GLOBAL_USERS_ADDED_COUNT,
                                        2L));

        var subjectIds = List.of(TEST_SUBJECT_IDS[3], TEST_SUBJECT_IDS[4]);

        when(audienceLoader.loadUsers(lastEvaluatedKey, tableToScan))
                .thenReturn(testUserProfilesFromSubjectIds(subjectIds));

        bulkUserEmailAudienceLoaderScheduledEventHandler.handleRequest(event, mockContext);

        subjectIds.forEach(
                id -> verify(bulkEmailUsersService, times(1)).addUser(id, BulkEmailStatus.PENDING));

        List.of(TEST_SUBJECT_IDS[0])
                .forEach(
                        id ->
                                verify(bulkEmailUsersService, never())
                                        .addUser(id, BulkEmailStatus.PENDING));

        var lastEmail = emailFromSubjectId(TEST_SUBJECT_IDS[4]);

        Map<String, Object> expectedUpdatedDetailsMap =
                Map.ofEntries(
                        Map.entry(LAST_EVALUATED_KEY, lastEmail),
                        Map.entry(GLOBAL_USERS_ADDED_COUNT, 4L),
                        Map.entry(TABLE_TO_SCAN, DynamoTable.USER_PROFILE));

        assertEquals(expectedUpdatedDetailsMap, event.getDetail());

        JSONObject detail =
                new JSONObject()
                        .appendField(LAST_EVALUATED_KEY, lastEmail)
                        .appendField(GLOBAL_USERS_ADDED_COUNT, 4L)
                        .appendField(TABLE_TO_SCAN, DynamoTable.USER_PROFILE);
        String payloadString = new JSONObject().appendField("detail", detail).toJSONString();

        verify(lambdaInvokerService, times(1)).invokeAsyncWithPayload(payloadString, functionName);
    }

    @Test
    void shouldNotReinvokeLambdaWhenNoItemsReturned() {
        when(configurationService.getBulkUserEmailMaxAudienceLoadUserCount()).thenReturn(100L);
        when(configurationService.getBulkUserEmailAudienceLoadUserBatchSize()).thenReturn(10L);

        var lastEvaluatedSubjectId = TEST_SUBJECT_IDS[2];
        var lastEvaluatedKey =
                Map.of("Email", AttributeValue.builder().s(lastEvaluatedSubjectId).build());
        var tableToScan = DynamoTable.USER_PROFILE;

        when(audienceLoader.loadUsers(lastEvaluatedKey, tableToScan)).thenReturn(Stream.empty());

        when(scheduledEvent.getDetail())
                .thenReturn(Map.of(LAST_EVALUATED_KEY, lastEvaluatedSubjectId));

        bulkUserEmailAudienceLoaderScheduledEventHandler.handleRequest(scheduledEvent, mockContext);

        Arrays.stream(TEST_SUBJECT_IDS)
                .forEach(
                        id ->
                                verify(bulkEmailUsersService, never())
                                        .addUser(id, BulkEmailStatus.PENDING));

        verify(scheduledEvent, never()).setDetail(any());
        verify(lambdaInvokerService, never()).invokeAsyncWithPayload(any(), any());
    }

    @Test
    void shouldThrowWhenValidateConfigFails() {
        when(configurationService.getBulkUserEmailMaxAudienceLoadUserCount()).thenReturn(100L);
        when(configurationService.getBulkUserEmailAudienceLoadUserBatchSize()).thenReturn(10L);
        doThrow(new IncludedTermsAndConditionsConfigMissingException())
                .when(audienceLoader)
                .validateConfig();

        assertThrows(
                IncludedTermsAndConditionsConfigMissingException.class,
                () ->
                        bulkUserEmailAudienceLoaderScheduledEventHandler.handleRequest(
                                scheduledEvent, mockContext),
                "Included terms and conditions configuration is missing");

        verify(bulkEmailUsersService, never()).addUser(SUBJECT_ID, BulkEmailStatus.PENDING);
    }

    private String emailFromSubjectId(String subjectId) {
        return String.format("%s@example.com", subjectId);
    }

    private Stream<BulkUserEmailAudienceUser> testUserProfilesFromSubjectIds(
            List<String> subjectIds) {
        return subjectIds.stream()
                .map(
                        subjectId ->
                                new BulkUserEmailAudienceUser(
                                        emailFromSubjectId(subjectId), subjectId));
    }
}

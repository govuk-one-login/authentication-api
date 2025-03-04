package uk.gov.di.authentication.utils.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.ScheduledEvent;
import net.minidev.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import uk.gov.di.authentication.shared.entity.BulkEmailStatus;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.services.BulkEmailUsersService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoAuthenticationService;
import uk.gov.di.authentication.shared.services.LambdaInvokerService;
import uk.gov.di.authentication.utils.exceptions.IncludedTermsAndConditionsConfigMissingException;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class BulkUserEmailAudienceLoaderScheduledEventHandlerTest {

    private BulkUserEmailAudienceLoaderScheduledEventHandler
            bulkUserEmailAudienceLoaderScheduledEventHandler;

    private final Context mockContext = mock(Context.class);

    private final BulkEmailUsersService bulkEmailUsersService = mock(BulkEmailUsersService.class);

    private final DynamoAuthenticationService dynamoAuthenticationService =
            mock(DynamoAuthenticationService.class);

    private final ConfigurationService configurationService = mock(ConfigurationService.class);

    private final LambdaInvokerService lambdaInvokerService = mock(LambdaInvokerService.class);

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
                        dynamoAuthenticationService,
                        configurationService,
                        lambdaInvokerService);
        when(configurationService.getBulkEmailLoaderLambdaName()).thenReturn(functionName);
    }

    @Test
    void shouldAddOneBulkEmailUser() {
        when(configurationService.getBulkUserEmailMaxAudienceLoadUserCount()).thenReturn(100L);
        when(configurationService.getBulkUserEmailAudienceLoadUserBatchSize()).thenReturn(10L);
        when(configurationService.getBulkUserEmailIncludedTermsAndConditions())
                .thenReturn(List.of("1.5", "1.6"));
        when(dynamoAuthenticationService.getBulkUserEmailAudienceStreamOnTermsAndConditionsVersion(
                        null, List.of("1.5", "1.6")))
                .thenReturn(testUserProfilesFromSubjectIds(List.of(SUBJECT_ID)));

        bulkUserEmailAudienceLoaderScheduledEventHandler.handleRequest(scheduledEvent, mockContext);

        verify(bulkEmailUsersService).addUser(SUBJECT_ID, BulkEmailStatus.PENDING);
    }

    @Test
    void shouldNotAddBulkEmailUserWhenMaxLoadAudienceUserCountIsZero() {
        when(configurationService.getBulkUserEmailMaxAudienceLoadUserCount()).thenReturn(0L);
        when(configurationService.getBulkUserEmailAudienceLoadUserBatchSize()).thenReturn(10L);
        when(configurationService.getBulkUserEmailIncludedTermsAndConditions())
                .thenReturn(List.of("1.5", "1.6"));
        when(dynamoAuthenticationService.getBulkUserEmailAudienceStreamOnTermsAndConditionsVersion(
                        null, List.of("1.5", "1.6")))
                .thenReturn(testUserProfilesFromSubjectIds(List.of(SUBJECT_ID)));

        bulkUserEmailAudienceLoaderScheduledEventHandler.handleRequest(scheduledEvent, mockContext);

        verify(bulkEmailUsersService, never()).addUser(SUBJECT_ID, BulkEmailStatus.PENDING);
    }

    @Test
    void shouldAddManyBulkEmailUsers() {
        when(configurationService.getBulkUserEmailMaxAudienceLoadUserCount()).thenReturn(100L);
        when(configurationService.getBulkUserEmailAudienceLoadUserBatchSize()).thenReturn(10L);
        when(configurationService.getBulkUserEmailIncludedTermsAndConditions())
                .thenReturn(List.of("1.5", "1.6"));
        when(dynamoAuthenticationService.getBulkUserEmailAudienceStreamOnTermsAndConditionsVersion(
                        null, List.of("1.5", "1.6")))
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
        when(configurationService.getBulkUserEmailIncludedTermsAndConditions())
                .thenReturn(List.of("1.5", "1.6"));
        when(dynamoAuthenticationService.getBulkUserEmailAudienceStreamOnTermsAndConditionsVersion(
                        null, List.of("1.5", "1.6")))
                .thenReturn(testUserProfilesFromSubjectIds(List.of(TEST_SUBJECT_IDS)));

        bulkUserEmailAudienceLoaderScheduledEventHandler.handleRequest(scheduledEvent, mockContext);

        verify(bulkEmailUsersService, times(3)).addUser(any(), eq(BulkEmailStatus.PENDING));
    }

    @Test
    void shouldReinvokeLambdaWithLastSubjectIdAndIncrementedCountWhenNoInitialStartKey() {
        when(configurationService.getBulkUserEmailMaxAudienceLoadUserCount()).thenReturn(100L);
        when(configurationService.getBulkUserEmailAudienceLoadUserBatchSize()).thenReturn(10L);
        when(configurationService.getBulkUserEmailIncludedTermsAndConditions())
                .thenReturn(List.of("1.5", "1.6"));

        var subjectIds = List.of(TEST_SUBJECT_IDS[0], TEST_SUBJECT_IDS[1], TEST_SUBJECT_IDS[2]);
        var userProfiles = testUserProfilesFromSubjectIds(subjectIds);
        when(dynamoAuthenticationService.getBulkUserEmailAudienceStreamOnTermsAndConditionsVersion(
                        null, List.of("1.5", "1.6")))
                .thenReturn(userProfiles);

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
                        "lastEvaluatedKey",
                        expectedLastEvaluatedEmail,
                        "globalUsersAddedCount",
                        Integer.toUnsignedLong(subjectIds.size())),
                event.getDetail());
        JSONObject detail =
                new JSONObject()
                        .appendField("lastEvaluatedKey", expectedLastEvaluatedEmail)
                        .appendField(
                                "globalUsersAddedCount", Integer.toUnsignedLong(subjectIds.size()));
        String payloadString = new JSONObject().appendField("detail", detail).toJSONString();

        verify(lambdaInvokerService, times(1)).invokeAsyncWithPayload(payloadString, functionName);
    }

    @Test
    void shouldReinvokeLambdaWithLastSubjectIdWithInitialStartKeyAndCount() {
        when(configurationService.getBulkUserEmailMaxAudienceLoadUserCount()).thenReturn(100L);
        when(configurationService.getBulkUserEmailAudienceLoadUserBatchSize()).thenReturn(10L);
        when(configurationService.getBulkUserEmailIncludedTermsAndConditions())
                .thenReturn(List.of("1.5", "1.6"));

        var lastEvaluatedEmail = emailFromSubjectId(TEST_SUBJECT_IDS[2]);
        var lastEvaluatedKey =
                Map.of("Email", AttributeValue.builder().s(lastEvaluatedEmail).build());

        var event =
                new ScheduledEvent()
                        .withDetail(
                                Map.of(
                                        "lastEvaluatedKey",
                                        lastEvaluatedEmail,
                                        "globalUsersAddedCount",
                                        2L));

        var subjectIds = List.of(TEST_SUBJECT_IDS[3], TEST_SUBJECT_IDS[4]);

        when(dynamoAuthenticationService.getBulkUserEmailAudienceStreamOnTermsAndConditionsVersion(
                        lastEvaluatedKey, List.of("1.5", "1.6")))
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
                        Map.entry("lastEvaluatedKey", lastEmail),
                        Map.entry("globalUsersAddedCount", 4L));

        assertEquals(expectedUpdatedDetailsMap, event.getDetail());

        JSONObject detail =
                new JSONObject()
                        .appendField("lastEvaluatedKey", lastEmail)
                        .appendField("globalUsersAddedCount", 4L);
        String payloadString = new JSONObject().appendField("detail", detail).toJSONString();

        verify(lambdaInvokerService, times(1)).invokeAsyncWithPayload(payloadString, functionName);
    }

    @Test
    void shouldNotReinvokeLambdaWhenNoItemsReturned() {
        when(configurationService.getBulkUserEmailMaxAudienceLoadUserCount()).thenReturn(100L);
        when(configurationService.getBulkUserEmailAudienceLoadUserBatchSize()).thenReturn(10L);
        when(configurationService.getBulkUserEmailIncludedTermsAndConditions())
                .thenReturn(List.of("1.5", "1.6"));

        var lastEvaluatedSubjectId = TEST_SUBJECT_IDS[2];
        var lastEvaluatedKey =
                Map.of("SubjectID", AttributeValue.builder().s(lastEvaluatedSubjectId).build());

        when(dynamoAuthenticationService.getBulkUserEmailAudienceStreamOnTermsAndConditionsVersion(
                        null, List.of("1.5", "1.6")))
                .thenReturn(Stream.empty());

        when(scheduledEvent.getDetail())
                .thenReturn(Map.of("lastEvaluatedKey", lastEvaluatedSubjectId));

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
    void shouldThrowWhenNoExlcudedTermsAndConditionsConfig() {
        when(configurationService.getBulkUserEmailMaxAudienceLoadUserCount()).thenReturn(100L);
        when(configurationService.getBulkUserEmailAudienceLoadUserBatchSize()).thenReturn(10L);

        assertThrows(
                IncludedTermsAndConditionsConfigMissingException.class,
                () ->
                        bulkUserEmailAudienceLoaderScheduledEventHandler.handleRequest(
                                scheduledEvent, mockContext),
                "Excluded terms and conditions configuration is missing");

        verify(bulkEmailUsersService, never()).addUser(SUBJECT_ID, BulkEmailStatus.PENDING);
    }

    private String emailFromSubjectId(String subjectId) {
        return String.format("%s@example.com", subjectId);
    }

    private Stream<UserProfile> testUserProfilesFromSubjectIds(List<String> subjectIds) {
        return subjectIds.stream()
                .map(
                        subjectId ->
                                new UserProfile()
                                        .withSubjectID(subjectId)
                                        .withEmail(emailFromSubjectId(subjectId)));
    }
}

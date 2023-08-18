package uk.gov.di.authentication.utils.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.ScheduledEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.BulkEmailStatus;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.services.BulkEmailUsersService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;

import java.util.List;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class BulkUserEmailAudienceLoaderScheduledEventHandlerTest {

    private BulkUserEmailAudienceLoaderScheduledEventHandler
            bulkUserEmailAudienceLoaderScheduledEventHandler;

    private final Context mockContext = mock(Context.class);

    private final BulkEmailUsersService bulkEmailUsersService = mock(BulkEmailUsersService.class);

    private final DynamoService dynamoService = mock(DynamoService.class);

    private final ConfigurationService configurationService = mock(ConfigurationService.class);

    private final ScheduledEvent scheduledEvent = mock(ScheduledEvent.class);

    private final String SUBJECT_ID = "subject-id";

    private final String[] TEST_SUBJECT_IDS = {
        "subject-id-1", "subject-id-2", "subject-id-3", "subject-id-4", "subject-id-5",
    };

    @BeforeEach
    void setUp() {
        bulkUserEmailAudienceLoaderScheduledEventHandler =
                new BulkUserEmailAudienceLoaderScheduledEventHandler(
                        bulkEmailUsersService, dynamoService, configurationService);
    }

    @Test
    void shouldAddOneBulkEmailUser() {
        when(configurationService.getBulkUserEmailMaxAudienceLoadUserCount()).thenReturn(10L);
        when(dynamoService.getBulkUserEmailAudienceStream())
                .thenReturn(List.of(new UserProfile().withSubjectID(SUBJECT_ID)).stream());

        bulkUserEmailAudienceLoaderScheduledEventHandler.handleRequest(scheduledEvent, mockContext);

        verify(bulkEmailUsersService).addUser(SUBJECT_ID, BulkEmailStatus.PENDING);
    }

    @Test
    void shouldNotAddBulkEmailUserWhenMaxLoadAudienceUserCountIsZero() {
        when(configurationService.getBulkUserEmailMaxAudienceLoadUserCount()).thenReturn(0L);
        when(dynamoService.getBulkUserEmailAudienceStream())
                .thenReturn(List.of(new UserProfile().withSubjectID(SUBJECT_ID)).stream());

        bulkUserEmailAudienceLoaderScheduledEventHandler.handleRequest(scheduledEvent, mockContext);

        verify(bulkEmailUsersService, times(0)).addUser(SUBJECT_ID, BulkEmailStatus.PENDING);
    }

    @Test
    void shouldAddManyBulkEmailUsers() {
        when(configurationService.getBulkUserEmailMaxAudienceLoadUserCount()).thenReturn(10L);
        when(dynamoService.getBulkUserEmailAudienceStream())
                .thenReturn(
                        List.of(
                                new UserProfile().withSubjectID(TEST_SUBJECT_IDS[0]),
                                new UserProfile().withSubjectID(TEST_SUBJECT_IDS[1]),
                                new UserProfile().withSubjectID(TEST_SUBJECT_IDS[2]),
                                new UserProfile().withSubjectID(TEST_SUBJECT_IDS[3]),
                                new UserProfile().withSubjectID(TEST_SUBJECT_IDS[4]))
                                .stream());

        bulkUserEmailAudienceLoaderScheduledEventHandler.handleRequest(scheduledEvent, mockContext);

        verify(bulkEmailUsersService, times(1))
                .addUser(TEST_SUBJECT_IDS[0], BulkEmailStatus.PENDING);
        verify(bulkEmailUsersService, times(1))
                .addUser(TEST_SUBJECT_IDS[1], BulkEmailStatus.PENDING);
        verify(bulkEmailUsersService, times(1))
                .addUser(TEST_SUBJECT_IDS[2], BulkEmailStatus.PENDING);
        verify(bulkEmailUsersService, times(1))
                .addUser(TEST_SUBJECT_IDS[3], BulkEmailStatus.PENDING);
        verify(bulkEmailUsersService, times(1))
                .addUser(TEST_SUBJECT_IDS[4], BulkEmailStatus.PENDING);
    }

    @Test
    void shouldAddOnlyMaxLoadAudienceUserCountBulkEmailUsers() {
        when(configurationService.getBulkUserEmailMaxAudienceLoadUserCount()).thenReturn(3L);
        when(dynamoService.getBulkUserEmailAudienceStream())
                .thenReturn(
                        List.of(
                                new UserProfile().withSubjectID(TEST_SUBJECT_IDS[0]),
                                new UserProfile().withSubjectID(TEST_SUBJECT_IDS[1]),
                                new UserProfile().withSubjectID(TEST_SUBJECT_IDS[2]),
                                new UserProfile().withSubjectID(TEST_SUBJECT_IDS[3]),
                                new UserProfile().withSubjectID(TEST_SUBJECT_IDS[4]))
                                .stream());

        bulkUserEmailAudienceLoaderScheduledEventHandler.handleRequest(scheduledEvent, mockContext);

        verify(bulkEmailUsersService, times(1))
                .addUser(TEST_SUBJECT_IDS[0], BulkEmailStatus.PENDING);
        verify(bulkEmailUsersService, times(1))
                .addUser(TEST_SUBJECT_IDS[1], BulkEmailStatus.PENDING);
        verify(bulkEmailUsersService, times(1))
                .addUser(TEST_SUBJECT_IDS[2], BulkEmailStatus.PENDING);
        verify(bulkEmailUsersService, times(0))
                .addUser(TEST_SUBJECT_IDS[3], BulkEmailStatus.PENDING);
        verify(bulkEmailUsersService, times(0))
                .addUser(TEST_SUBJECT_IDS[4], BulkEmailStatus.PENDING);
    }
}

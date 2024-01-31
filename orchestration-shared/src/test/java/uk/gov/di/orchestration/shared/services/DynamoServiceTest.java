package uk.gov.di.orchestration.shared.services;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import uk.gov.di.orchestration.shared.entity.UserCredentials;
import uk.gov.di.orchestration.shared.entity.UserProfile;

import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;

class DynamoServiceTest {
    private static final DynamoDbTable<UserProfile> dynamoUserProfileTable =
            mock(DynamoDbTable.class);
    private static final DynamoDbTable<UserCredentials> dynamoUserCredentialsTable =
            mock(DynamoDbTable.class);
    private static final DynamoDbEnhancedClient dynamoDbEnhancedClient =
            mock(DynamoDbEnhancedClient.class);
    private DynamoService dynamoService;

    @BeforeEach
    void setup() {
        dynamoService =
                spy(
                        new DynamoService(
                                dynamoUserProfileTable,
                                dynamoUserCredentialsTable,
                                dynamoDbEnhancedClient));
    }

    @Test
    void shouldReturnEmptyOptionalIfTryingToGetUserProfileWithNullEmail() {
        var response = dynamoService.getUserProfileByEmailMaybe(null);
        assertThat(response, equalTo(Optional.empty()));
    }
}

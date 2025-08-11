package uk.gov.di.authentication.shared.dynamodb;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.services.dynamodb.model.ResourceNotFoundException;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(SystemStubsExtension.class)
public class DynamoClientHelperTest {
    @SystemStub static EnvironmentVariables environment = new EnvironmentVariables();

    @Test
    void warmUpDescribesTable() {
        // Arrange
        var table = mock(DynamoDbTable.class);

        // Act
        DynamoClientHelper.warmUp(table);

        // Assert
        verify(table).describeTable();
    }

    @Test
    void warmUpThrowsErrorIfTableDoesNotExistInDeployedEnvs() {
        // Arrange
        var table = mock(DynamoDbTable.class);
        when(table.describeTable()).thenThrow(ResourceNotFoundException.class);

        // Act & Assert
        assertThrows(ResourceNotFoundException.class, () -> DynamoClientHelper.warmUp(table));
    }

    @Test
    void warmUpCreatesTableIfTableDoesNotExistInLocalEnv() {
        // Arrange
        environment.set("ENVIRONMENT", "local");
        var table = mock(DynamoDbTable.class);
        when(table.describeTable()).thenThrow(ResourceNotFoundException.class);

        // Act
        DynamoClientHelper.warmUp(table);

        // Assert
        verify(table).createTable();
    }
}

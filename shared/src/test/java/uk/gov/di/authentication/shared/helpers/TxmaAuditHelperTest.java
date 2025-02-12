package uk.gov.di.authentication.shared.helpers;

import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.MockedStatic;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.Optional;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

public class TxmaAuditHelperTest {
    private static final String TEST_SUBJECT = "test-subject";
    private static final String TEST_UNKNOWN = AuditService.UNKNOWN;

    @ParameterizedTest
    @MethodSource("userProfileAndClientCombinations")
    public void shouldReturnRpPairwiseIdWhenUserProfileAndClientProvided(
            boolean hasUserProfile, boolean hasClient, String expectedRpPairwiseId) {
        // Arrange
        var mockUserContext = mock(UserContext.class);

        Optional<UserProfile> optionalUserProfile =
                hasUserProfile ? Optional.of(mock(UserProfile.class)) : Optional.empty();
        when(mockUserContext.getUserProfile()).thenReturn(optionalUserProfile);

        Optional<ClientRegistry> optionalClient =
                hasClient ? Optional.of(mock(ClientRegistry.class)) : Optional.empty();
        when(mockUserContext.getClient()).thenReturn(optionalClient);

        String rpPairwiseId;
        try (MockedStatic<ClientSubjectHelper> mockClientSubjectHelper =
                mockStatic(ClientSubjectHelper.class, CALLS_REAL_METHODS)) {
            mockClientSubjectHelper
                    .when(() -> ClientSubjectHelper.getSubject(any(), any(), any(), any()))
                    .thenReturn(new Subject(TEST_SUBJECT));

            // Act
            rpPairwiseId = TxmaAuditHelper.getRpPairwiseId(mock(), mock(), mockUserContext);
        }

        // Assert
        assertEquals(expectedRpPairwiseId, rpPairwiseId);
    }

    private static Stream<Arguments> userProfileAndClientCombinations() {
        return Stream.of(
                Arguments.of(true, true, TEST_SUBJECT),
                Arguments.of(false, true, TEST_UNKNOWN),
                Arguments.of(true, false, TEST_UNKNOWN),
                Arguments.of(false, false, TEST_UNKNOWN));
    }
}

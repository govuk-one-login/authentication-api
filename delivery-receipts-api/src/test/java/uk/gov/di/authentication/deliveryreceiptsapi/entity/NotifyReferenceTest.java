package uk.gov.di.authentication.deliveryreceiptsapi.entity;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class NotifyReferenceTest {
    @ParameterizedTest
    @MethodSource("shouldBuildCorrectNotifyReferenceBasedOnReferenceValues")
    void shouldBuildCorrectNotifyReferenceBasedOnReference(
            String reference,
            String expectedUniqueNotificationReference,
            String expectedClientSessionId) {
        // Act
        var actual = new NotifyReference(reference);

        // Assert
        assertEquals(expectedUniqueNotificationReference, actual.getUniqueNotificationReference());
        assertEquals(expectedClientSessionId, actual.getClientSessionId());
    }

    private static Stream<Arguments> shouldBuildCorrectNotifyReferenceBasedOnReferenceValues() {
        return Stream.of(
                Arguments.of(null, null, null),
                Arguments.of("", null, null),
                Arguments.of("CSI", null, "CSI"),
                Arguments.of("UNR/CSI", "UNR", "CSI"),
                Arguments.of("UNR/CSI/foo", "UNR", "CSI"));
    }
}

package uk.gov.di.authentication.accountdata.helpers;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static uk.gov.di.authentication.accountdata.helpers.CommonTestVariables.PRIMARY_PASSKEY_ID;
import static uk.gov.di.authentication.accountdata.helpers.CommonTestVariables.TEST_AAGUID;

public class PasskeysHelperTest {

    @Nested
    class BuildSortKey {
        private static Stream<Arguments> buildSortKeyArguments() {
            return Stream.of(
                    Arguments.of("myPasskey", "PASSKEY#myPasskey"),
                    Arguments.of("1234", "PASSKEY#1234"),
                    Arguments.of(
                            PRIMARY_PASSKEY_ID, String.format("PASSKEY#%s", PRIMARY_PASSKEY_ID)));
        }

        @ParameterizedTest
        @MethodSource("buildSortKeyArguments")
        void shouldBuildSortKey(String passkeyId, String expectedSortKey) {
            // Given
            // When
            var result = PasskeysHelper.buildSortKey(passkeyId);

            // Then
            assertThat(result, equalTo(expectedSortKey));
        }
    }

    @Nested
    class IsAaguidValid {

        private static Stream<Arguments> aaguidArguments() {
            return Stream.of(
                    Arguments.of(null, false),
                    Arguments.of("", false),
                    Arguments.of("some-invalid-aaguid", false),
                    Arguments.of(TEST_AAGUID, true));
        }

        @ParameterizedTest
        @MethodSource("aaguidArguments")
        void shouldValidateAaguidCorrectly(String aaguid, boolean expectedResult) {
            // Given
            // When
            var result = PasskeysHelper.isAaguidValid(aaguid);

            // Then
            assertThat(result, equalTo(expectedResult));
        }
    }
}

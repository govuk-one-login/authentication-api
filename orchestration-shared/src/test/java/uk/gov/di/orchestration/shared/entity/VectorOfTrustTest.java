package uk.gov.di.orchestration.shared.entity;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.core.Is.is;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class VectorOfTrustTest {

    private static final VectorOfTrust VOT_CL = new VectorOfTrust(CredentialTrustLevel.LOW_LEVEL);
    private static final VectorOfTrust VOT_CL_CM =
            new VectorOfTrust(CredentialTrustLevel.MEDIUM_LEVEL);
    private static final VectorOfTrust VOT_P0_CL =
            new VectorOfTrust(CredentialTrustLevel.LOW_LEVEL, LevelOfConfidence.NONE);
    private static final VectorOfTrust VOT_P0_CL_CM =
            new VectorOfTrust(CredentialTrustLevel.MEDIUM_LEVEL, LevelOfConfidence.NONE);
    private static final VectorOfTrust VOT_P2_CL_CM =
            new VectorOfTrust(CredentialTrustLevel.MEDIUM_LEVEL, LevelOfConfidence.MEDIUM_LEVEL);
    private static final VectorOfTrust VOT_PCL200_CL_CM =
            new VectorOfTrust(CredentialTrustLevel.MEDIUM_LEVEL, LevelOfConfidence.HMRC200);
    private static final VectorOfTrust VOT_PCL250_CL_CM =
            new VectorOfTrust(CredentialTrustLevel.MEDIUM_LEVEL, LevelOfConfidence.HMRC250);

    @ParameterizedTest
    @MethodSource("credentialTrustLevelCases")
    void getCredentialTrustLevel(
            VectorOfTrust vectorOfTrust, CredentialTrustLevel expectedCredentialTrustLevel) {
        assertThat(
                vectorOfTrust.getCredentialTrustLevel(), is(equalTo(expectedCredentialTrustLevel)));
    }

    private static Stream<Arguments> credentialTrustLevelCases() {
        return Stream.of(
                Arguments.of(VOT_CL, CredentialTrustLevel.LOW_LEVEL),
                Arguments.of(VOT_CL_CM, CredentialTrustLevel.MEDIUM_LEVEL),
                Arguments.of(VOT_P0_CL, CredentialTrustLevel.LOW_LEVEL),
                Arguments.of(VOT_P0_CL_CM, CredentialTrustLevel.MEDIUM_LEVEL),
                Arguments.of(VOT_P2_CL_CM, CredentialTrustLevel.MEDIUM_LEVEL),
                Arguments.of(VOT_PCL200_CL_CM, CredentialTrustLevel.MEDIUM_LEVEL),
                Arguments.of(VOT_PCL250_CL_CM, CredentialTrustLevel.MEDIUM_LEVEL));
    }

    @ParameterizedTest
    @MethodSource("levelOfConfidenceCases")
    void getLevelOfConfidence(
            VectorOfTrust vectorOfTrust, LevelOfConfidence expectedLevelOfConfidence) {
        assertThat(vectorOfTrust.getLevelOfConfidence(), is(equalTo(expectedLevelOfConfidence)));
    }

    private static Stream<Arguments> levelOfConfidenceCases() {
        return Stream.of(
                Arguments.of(VOT_CL, LevelOfConfidence.NONE),
                Arguments.of(VOT_CL_CM, LevelOfConfidence.NONE),
                Arguments.of(VOT_P0_CL, LevelOfConfidence.NONE),
                Arguments.of(VOT_P0_CL_CM, LevelOfConfidence.NONE),
                Arguments.of(VOT_P2_CL_CM, LevelOfConfidence.MEDIUM_LEVEL),
                Arguments.of(VOT_PCL200_CL_CM, LevelOfConfidence.HMRC200),
                Arguments.of(VOT_PCL250_CL_CM, LevelOfConfidence.HMRC250));
    }

    @ParameterizedTest
    @MethodSource("equalsAndHashCodeAnCompareToTestCases")
    void equalsAndHashCodeAndCompareToShouldBehaveCorrectly(
            VectorOfTrust vot1, VectorOfTrust vot2, boolean expectedEquals) {
        // test equals
        assertThat(vot1.equals(vot2), is(equalTo(expectedEquals)));
        assertThat(vot2.equals(vot1), is(equalTo(expectedEquals)));

        if (expectedEquals) {
            // test hashCode
            assertThat(vot1.hashCode(), is(equalTo(vot2.hashCode())));
        }
    }

    static Stream<Arguments> equalsAndHashCodeAnCompareToTestCases() {
        return Stream.of(
                arguments(VOT_CL, VOT_CL, true),
                arguments(VOT_CL, VOT_P0_CL, true),
                arguments(VOT_CL_CM, VOT_CL_CM, true),
                arguments(VOT_CL_CM, VOT_P0_CL_CM, true),
                arguments(VOT_P2_CL_CM, VOT_P2_CL_CM, true),
                arguments(VOT_CL, VOT_CL_CM, false),
                arguments(VOT_PCL250_CL_CM, VOT_PCL200_CL_CM, false),
                arguments(VOT_CL_CM, VOT_P2_CL_CM, false));
    }
}

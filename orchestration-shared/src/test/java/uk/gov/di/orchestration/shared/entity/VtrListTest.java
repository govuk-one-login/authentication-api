package uk.gov.di.orchestration.shared.entity;

import com.google.gson.Gson;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class VtrListTest {

    private static final Gson GSON = new Gson();
    private static final VectorOfTrust VOT_CL = new VectorOfTrust(CredentialTrustLevel.LOW_LEVEL);
    private static final VectorOfTrust VOT_CL_CM =
            new VectorOfTrust(CredentialTrustLevel.MEDIUM_LEVEL);
    private static final VectorOfTrust VOT_P0_CL =
            new VectorOfTrust(CredentialTrustLevel.LOW_LEVEL, LevelOfConfidence.NONE);
    private static final VectorOfTrust VOT_P0_CL_CM =
            new VectorOfTrust(CredentialTrustLevel.MEDIUM_LEVEL, LevelOfConfidence.NONE);
    private static final VectorOfTrust VOT_P2_CL_CM =
            new VectorOfTrust(CredentialTrustLevel.MEDIUM_LEVEL, LevelOfConfidence.MEDIUM_LEVEL);
    private static final VectorOfTrust VOT_PCL250_CL_CM =
            new VectorOfTrust(CredentialTrustLevel.MEDIUM_LEVEL, LevelOfConfidence.HMRC250);

    @ParameterizedTest
    @MethodSource("parseSuccessTestCases")
    void parseFromAuthRequestAttributeReturnCorrectVtrList(
            List<String> vtr, VtrList expectedVtrList) {
        var actualVtrList = VtrList.parseFromAuthRequestAttribute(vtr);

        assertThat(actualVtrList.getVtr(), is(equalTo(expectedVtrList.getVtr())));
    }

    static Stream<Arguments> parseSuccessTestCases() {
        return Stream.of(
                arguments(null, VtrList.of(VOT_CL_CM)),
                arguments(Collections.emptyList(), VtrList.of(VOT_CL_CM)),
                arguments(List.of("[\"P0.Cl\"]"), VtrList.of(VOT_P0_CL)),
                arguments(List.of("[\"Cl.P0.Cm\"]"), VtrList.of(VOT_P0_CL_CM)),
                arguments(List.of("[\"P2.Cl.Cm\"]"), VtrList.of(VOT_P2_CL_CM)),
                arguments(List.of("[\"PCL250.Cl.Cm\"]"), VtrList.of(VOT_PCL250_CL_CM)),
                arguments(
                        List.of("[\"P2.Cl.Cm\",\"PCL250.Cl.Cm\"]"),
                        VtrList.of(VOT_P2_CL_CM, VOT_PCL250_CL_CM)));
    }

    @ParameterizedTest
    @MethodSource("getVtrTestCases")
    void getVtrReturnsFullVtr(VtrList vtrList, List<VectorOfTrust> expectedVtr) {

        assertThat(vtrList.getVtr(), is(equalTo(expectedVtr)));
    }

    static Stream<Arguments> getVtrTestCases() {
        return Stream.of(
                arguments(VtrList.of(VOT_CL_CM), List.of(VOT_CL_CM)),
                arguments(VtrList.of(VOT_P0_CL), List.of(VOT_P0_CL)),
                arguments(VtrList.of(VOT_P0_CL_CM), List.of(VOT_P0_CL_CM)),
                arguments(VtrList.of(VOT_CL_CM, VOT_CL), List.of(VOT_CL_CM, VOT_CL)));
    }

    @ParameterizedTest
    @MethodSource({"parseSummaryFailureTestCases"})
    void parseFromAuthRequestAttributeThrowsOnInvalidVtr(List<String> vtr) {
        assertThrows(
                IllegalArgumentException.class, () -> VtrList.parseFromAuthRequestAttribute(vtr));
    }

    static Stream<Arguments> parseSummaryFailureTestCases() {
        return Stream.of(
                // Unknown IDs
                arguments(List.of("[\"R2.D2\"]")),
                // Missing Auth
                arguments(List.of("[\"P0\"]")),
                // Bad Formatting
                arguments(List.of("(CL|CM)")),
                // Illegal combination of identity / non-identity VoTs
                arguments(List.of("[\"Cl.P0\", \"Cl.Cm.P2\"]")));
    }

    @ParameterizedTest
    @MethodSource("requiresIdentityTestCases")
    void requiresIdentityReturnsCorrectValue(VtrList vtrList, boolean expectedRequiresIdentity) {

        assertThat(vtrList.identityRequired(), is(equalTo(expectedRequiresIdentity)));
    }

    static Stream<Arguments> requiresIdentityTestCases() {
        return Stream.of(
                arguments(VtrList.of(VOT_CL_CM), false),
                arguments(VtrList.of(VOT_P0_CL), false),
                arguments(VtrList.of(VOT_P2_CL_CM), true),
                arguments(VtrList.of(VOT_PCL250_CL_CM), true),
                arguments(VtrList.of(VOT_P2_CL_CM, VOT_PCL250_CL_CM), true),
                arguments(VtrList.of(VOT_CL_CM, VOT_P0_CL), false));
    }

    @ParameterizedTest
    @MethodSource("requiresMfaTestCases")
    void requiresMfaCorrectValue(VtrList vtrList, boolean expectedRequiresIdentity) {

        assertThat(vtrList.mfaRequired(), is(equalTo(expectedRequiresIdentity)));
    }

    static Stream<Arguments> requiresMfaTestCases() {
        return Stream.of(
                arguments(VtrList.of(VOT_CL_CM), true),
                arguments(VtrList.of(VOT_P0_CL), false),
                arguments(VtrList.of(VOT_P2_CL_CM), true),
                arguments(VtrList.of(VOT_PCL250_CL_CM), true),
                arguments(VtrList.of(VOT_P2_CL_CM, VOT_PCL250_CL_CM), true),
                arguments(VtrList.of(VOT_P0_CL, VOT_CL_CM), false));
    }

    @Test
    void getCredentialTrustLevelReturnCorrectValue() {
        var vtrList = VtrList.of(VOT_CL_CM, VOT_CL);
        assertThat(vtrList.getCredentialTrustLevel(), is(equalTo(CredentialTrustLevel.LOW_LEVEL)));
    }

    @Test
    void getSelectedLevelsOfConfidencesReturnCorrectValue() {
        var vtrList1 = VtrList.of(VOT_CL_CM, VOT_CL);
        assertThat(vtrList1.getLevelsOfConfidence(), is(equalTo(List.of(LevelOfConfidence.NONE))));

        var vtrList2 = VtrList.of(VOT_P2_CL_CM, VOT_PCL250_CL_CM);
        assertThat(
                vtrList2.getLevelsOfConfidence(),
                containsInAnyOrder(LevelOfConfidence.HMRC250, LevelOfConfidence.MEDIUM_LEVEL));
    }

    @ParameterizedTest
    @MethodSource("getExpectedVectorOfTrustTestCases")
    void getEffectiveVectorOfTrustReturnsCorrectValue(
            VtrList vtrList, VectorOfTrust expectedVectorOfTrust) {
        assertThat(vtrList.getEffectiveVectorOfTrust(), is(equalTo(expectedVectorOfTrust)));
    }

    static Stream<Arguments> getExpectedVectorOfTrustTestCases() {
        return Stream.of(
                arguments(VtrList.of(VOT_CL_CM), VOT_CL_CM),
                arguments(VtrList.of(VOT_P0_CL), VOT_P0_CL),
                arguments(VtrList.of(VOT_P0_CL, VOT_CL_CM), VOT_P0_CL),
                arguments(VtrList.of(VOT_CL_CM, VOT_P0_CL), VOT_P0_CL));
    }

    @Test
    void ShouldSerializeCorrectly() {
        var expectedJson =
                """
                [
                    {
                        "credentialTrustLevel": "MEDIUM_LEVEL",
                        "levelOfConfidence": "MEDIUM_LEVEL"
                    },
                    {
                        "credentialTrustLevel": "MEDIUM_LEVEL",
                        "levelOfConfidence": "HMRC250"
                    }
                 ]
                 """;

        var actualJson = GSON.toJson(VtrList.of(VOT_P2_CL_CM, VOT_PCL250_CL_CM));

        assertThat(
                JsonParser.parseString(actualJson),
                is(equalTo(JsonParser.parseString(expectedJson))));
    }

    @Test
    void ShouldDeserializeCorrectly() {
        var expectedVtrList = VtrList.of(VOT_P2_CL_CM, VOT_PCL250_CL_CM);

        var actualVtrList =
                GSON.fromJson(
                        """
                [
                    {
                        "credentialTrustLevel": "MEDIUM_LEVEL",
                        "levelOfConfidence": "MEDIUM_LEVEL"
                    },
                    {
                        "credentialTrustLevel": "MEDIUM_LEVEL",
                        "levelOfConfidence": "HMRC250"
                    }
                 ]
                 """,
                        VtrList.class);

        assertThat(expectedVtrList.getVtr().size(), is(equalTo(actualVtrList.getVtr().size())));
        for (int i = 0; i < expectedVtrList.getVtr().size(); i++) {
            assertThat(
                    expectedVtrList.getVtr().get(i).getCredentialTrustLevel(),
                    is(equalTo(actualVtrList.getVtr().get(i).getCredentialTrustLevel())));
            assertThat(
                    expectedVtrList.getVtr().get(i).getLevelOfConfidence(),
                    is(equalTo(actualVtrList.getVtr().get(i).getLevelOfConfidence())));
        }
    }
}

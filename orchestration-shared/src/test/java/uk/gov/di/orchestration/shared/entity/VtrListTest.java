package uk.gov.di.orchestration.shared.entity;

import com.google.gson.Gson;
import com.google.gson.JsonParser;
import com.google.gson.annotations.JsonAdapter;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.orchestration.shared.entity.vectoroftrust.CredentialTrustLevel;
import uk.gov.di.orchestration.shared.entity.vectoroftrust.LevelOfConfidence;
import uk.gov.di.orchestration.shared.entity.vectoroftrust.VectorOfTrust;
import uk.gov.di.orchestration.shared.entity.vectoroftrust.VtrList;
import uk.gov.di.orchestration.shared.serialization.VtrListAdapter;

import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.CredentialTrustLevelCode.C1;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.CredentialTrustLevelCode.C2;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.CredentialTrustLevelCode.CL;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.CredentialTrustLevelCode.CL_CM;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.LevelOfConfidenceCode.EMPTY;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.LevelOfConfidenceCode.P0;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.LevelOfConfidenceCode.P2;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.LevelOfConfidenceCode.PCL200;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.LevelOfConfidenceCode.PCL250;

@JsonAdapter(VtrListAdapter.class)
class VtrListTest {

    private static Gson gson;
    private static VectorOfTrust votCl;
    private static VectorOfTrust votC1;
    private static VectorOfTrust votClCm;
    private static VectorOfTrust votC2;
    private static VectorOfTrust votP0Cl;
    private static VectorOfTrust votP0ClCm;
    private static VectorOfTrust votP0C2;
    private static VectorOfTrust votP2ClCm;
    private static VectorOfTrust votP2C2;
    private static VectorOfTrust votPCL200C2;
    private static VectorOfTrust votPCL250ClCm;

    @BeforeAll
    static void Setup() {
        gson = new Gson();
        votCl = VectorOfTrust.of(CL);
        votC1 = VectorOfTrust.of(C1);
        votClCm = VectorOfTrust.of(CL_CM);
        votC2 = VectorOfTrust.of(C2);
        votP0Cl = VectorOfTrust.of(CL, P0);
        votP0ClCm = VectorOfTrust.of(CL_CM, P0);
        votP0C2 = VectorOfTrust.of(C2, P0);
        votP2ClCm = VectorOfTrust.of(CL_CM, P2);
        votP2C2 = VectorOfTrust.of(C2, P2);
        votPCL200C2 = VectorOfTrust.of(C2, PCL200);
        votPCL250ClCm = VectorOfTrust.of(CL_CM, PCL250);
    }

    @ParameterizedTest
    @MethodSource("parseSuccessTestCases")
    void parseFromAuthRequestAttributeReturnCorrectVtrList(
            List<String> vtr, VtrList expectedVtrList) {
        var actualVtrList = VtrList.parseFromAuthRequestAttribute(vtr);

        assertThat(actualVtrList.getVtr(), is(equalTo(expectedVtrList.getVtr())));
    }

    static Stream<Arguments> parseSuccessTestCases() {
        return Stream.of(
                arguments(null, VtrList.of(votClCm)),
                arguments(Collections.emptyList(), VtrList.of(votClCm)),
                arguments(List.of("[\"C2\"]"), VtrList.of(votC2)),
                arguments(List.of("[\"P0.Cl\"]"), VtrList.of(votP0Cl)),
                arguments(List.of("[\"C1\",\"C2\",\"C2\"]"), VtrList.of(votC1, votC2, votC2)),
                arguments(List.of("[\"C2\",\"Cl.P0.Cm\"]"), VtrList.of(votC2, votP0ClCm)),
                arguments(List.of("[\"Cl.P0.Cm\", \"C2\"]"), VtrList.of(votP0ClCm, votC2)),
                arguments(
                        List.of("[\"P0.C2\",\"C2\",\"C1\",\"Cl.Cm\",\"Cl\"]"),
                        VtrList.of(votP0C2, votC2, votC1, votClCm, votCl)),
                arguments(List.of("[\"C2.P2\",\"P2.Cl.Cm\"]"), VtrList.of(votP2C2, votP2ClCm)),
                arguments(
                        List.of("[\"PCL250.Cl.Cm\",\"PCL200.C2\"]"),
                        VtrList.of(votPCL250ClCm, votPCL200C2)),
                arguments(
                        List.of("[\"P2.Cl.Cm\",\"PCL250.Cl.Cm\",\"PCL200.C2\"]"),
                        VtrList.of(votP2ClCm, votPCL250ClCm, votPCL200C2)));
    }

    @ParameterizedTest
    @MethodSource("getVtrTestCases")
    void getVtrReturnsFullVtr(VtrList vtrList, List<VectorOfTrust> expectedVtr) {

        assertThat(vtrList.getVtr(), is(equalTo(expectedVtr)));
    }

    static Stream<Arguments> getVtrTestCases() {
        return Stream.of(
                arguments(VtrList.of(votClCm), List.of(votClCm)),
                arguments(VtrList.of(votC2), List.of(votC2)),
                arguments(VtrList.of(votP0Cl), List.of(votP0Cl)),
                arguments(VtrList.of(votC1, votC2, votC2), List.of(votC1, votC2, votC2)),
                arguments(VtrList.of(votC2, votP0ClCm), List.of(votC2, votP0ClCm)),
                arguments(VtrList.of(votP0ClCm, votC2), List.of(votP0ClCm, votC2)),
                arguments(
                        VtrList.of(votP0C2, votC2, votC1, votClCm, votCl),
                        List.of(votP0C2, votC2, votC1, votClCm, votCl)),
                arguments(VtrList.of(votP2C2, votP2ClCm), List.of(votP2C2, votP2ClCm)),
                arguments(
                        VtrList.of(votPCL250ClCm, votPCL200C2),
                        List.of(votPCL250ClCm, votPCL200C2)),
                arguments(
                        VtrList.of(votP2ClCm, votPCL250ClCm, votPCL200C2),
                        List.of(votP2ClCm, votPCL250ClCm, votPCL200C2)));
    }

    @ParameterizedTest
    @MethodSource("getSelectionTestCases")
    void getSelectionReturnsMinimalReducedSelectionOfVtr(
            VtrList vtrList, List<VectorOfTrust> expectedSelection) {

        assertThat(vtrList.getSelection(), is(equalTo(expectedSelection)));
    }

    static Stream<Arguments> getSelectionTestCases() {
        return Stream.of(
                arguments(VtrList.of(votClCm), List.of(votClCm)),
                arguments(VtrList.of(votC2), List.of(votC2)),
                arguments(VtrList.of(votP0Cl), List.of(votP0Cl)),
                arguments(VtrList.of(votC1, votC2, votC2), List.of(votC1)),
                arguments(VtrList.of(votC2, votP0ClCm), List.of(votC2)),
                arguments(VtrList.of(votP0ClCm, votC2), List.of(votP0ClCm)),
                arguments(VtrList.of(votP0C2, votC2, votC1, votClCm, votCl), List.of(votC1)),
                arguments(VtrList.of(votP2C2, votP2ClCm), List.of(votP2C2)),
                arguments(VtrList.of(votPCL250ClCm, votPCL200C2), List.of(votPCL200C2)),
                arguments(
                        VtrList.of(votP2ClCm, votPCL250ClCm, votPCL200C2),
                        List.of(votP2ClCm, votPCL200C2)));
    }

    @ParameterizedTest
    @MethodSource({"parseSummaryFailureTestCases"})
    void parseFromAuthRequestAttributeThrowsOnInvalidVtr(
            List<String> vtr, String expectedExceptionMessage) {
        var exception =
                assertThrows(
                        IllegalArgumentException.class,
                        () -> VtrList.parseFromAuthRequestAttribute(vtr));
        assertThat(exception.getMessage(), is(equalTo(expectedExceptionMessage)));
    }

    static Stream<Arguments> parseSummaryFailureTestCases() {
        return Stream.of(
                // Unknown IDs
                arguments(List.of("[\"R2.D2\"]"), "Invalid VTR attribute."),
                // Unsupported CTL
                arguments(List.of("[\"C3.P0\"]"), "Unsupported \"Credential Trust Level\" \"C3\"."),
                // Unsupported LOC
                arguments(List.of("[\"C1.P1\"]"), "Unsupported \"Level of Confidence\" \"P1\"."),
                // Missing Auth
                arguments(List.of("[\"P0\"]"), "Invalid VTR attribute."),
                // Multi Entry Request
                arguments(List.of("[\"C2\"]", "[\"P0.Cl.Cm\"]"), "Invalid VTR attribute."),
                // Bad Formatting
                arguments(List.of("(CL|CM)"), "Invalid VTR attribute."));
    }

    @ParameterizedTest
    @MethodSource("getEffectiveTestCases")
    void getEffectiveVectorOfTrustReturnsFirstSelection(
            VtrList vtrList, VectorOfTrust expectedVot) {

        assertThat(vtrList.getEffectiveVectorOfTrust(), is(equalTo(expectedVot)));
    }

    static Stream<Arguments> getEffectiveTestCases() {
        return Stream.of(
                arguments(VtrList.of(votClCm), votClCm),
                arguments(
                        VtrList.of(votP2ClCm, votPCL250ClCm, votPCL200C2), votP2ClCm, votPCL200C2));
    }

    @ParameterizedTest
    @MethodSource("requiresIdentityTestCases")
    void requiresIdentityReturnsCorrectValue(VtrList vtrList, boolean expectedRequiresIdentity) {

        assertThat(vtrList.identityRequired(), is(equalTo(expectedRequiresIdentity)));
    }

    static Stream<Arguments> requiresIdentityTestCases() {
        return Stream.of(
                arguments(VtrList.of(votClCm), false),
                arguments(VtrList.of(votC2), false),
                arguments(VtrList.of(votP0Cl), false),
                arguments(VtrList.of(votC1, votC2, votC2), false),
                arguments(VtrList.of(votC2, votP0ClCm), false),
                arguments(VtrList.of(votP0ClCm, votC2), false),
                arguments(VtrList.of(votP0C2, votC2, votC1, votClCm, votCl), false),
                arguments(VtrList.of(votP2C2, votP2ClCm), true),
                arguments(VtrList.of(votPCL250ClCm, votPCL200C2), true),
                arguments(VtrList.of(votP2ClCm, votPCL250ClCm, votPCL200C2), true),
                arguments(VtrList.of(votP2ClCm, votPCL250ClCm, votPCL200C2, votP0Cl), false));
    }

    @ParameterizedTest
    @MethodSource("requiresMfaTestCases")
    void requiresMfaCorrectValue(VtrList vtrList, boolean expectedRequiresIdentity) {

        assertThat(vtrList.mfaRequired(), is(equalTo(expectedRequiresIdentity)));
    }

    static Stream<Arguments> requiresMfaTestCases() {
        return Stream.of(
                arguments(VtrList.of(votClCm), true),
                arguments(VtrList.of(votC2), true),
                arguments(VtrList.of(votP0Cl), false),
                arguments(VtrList.of(votC1, votC2, votC2), false),
                arguments(VtrList.of(votC2, votP0ClCm), true),
                arguments(VtrList.of(votP0ClCm, votC2), true),
                arguments(VtrList.of(votP0C2, votC2, votC1, votClCm, votCl), false),
                arguments(VtrList.of(votP2C2, votP2ClCm), true),
                arguments(VtrList.of(votPCL250ClCm, votPCL200C2), true),
                arguments(VtrList.of(votP2ClCm, votPCL250ClCm, votPCL200C2), true),
                arguments(VtrList.of(votP2ClCm, votPCL250ClCm, votPCL200C2, votP0Cl), false));
    }

    @Test
    void getSelectedCredentialTrustLevelCodeReturnCorrectValue() {
        var vtrList = VtrList.of(votPCL200C2, votP2C2);
        assertThat(vtrList.getSelectedCredentialTrustLevelCode(), is(equalTo(C2)));
    }

    @Test
    void getSelectedLevelOfConfidencesCodeReturnCorrectValue() {
        var vtrList1 = VtrList.of(votC2);
        assertThat(vtrList1.getSelectedLevelOfConfidenceCodes(), is(equalTo(List.of(EMPTY))));

        var vtrList2 = VtrList.of(votPCL200C2, votP2C2, votPCL250ClCm);
        assertThat(vtrList2.getSelectedLevelOfConfidenceCodes(), is(equalTo(List.of(PCL200, P2))));
    }

    @Test
    void getSelectedCredentialTrustLevelReturnCorrectValue() {
        var vtrList = VtrList.of(votPCL200C2, votP2C2, votPCL250ClCm);
        assertThat(
                vtrList.getSelectedCredentialTrustLevel(),
                is(equalTo(CredentialTrustLevel.MEDIUM_LEVEL)));
    }

    @Test
    void getSelectedLevelOfConfidencesReturnCorrectValue() {
        var vtrList1 = VtrList.of(votC2);
        assertThat(
                vtrList1.getSelectedLevelOfConfidences(),
                is(equalTo(List.of(LevelOfConfidence.NONE))));

        var vtrList2 = VtrList.of(votPCL200C2, votP2C2, votPCL250ClCm);
        assertThat(
                vtrList2.getSelectedLevelOfConfidences(),
                is(equalTo(List.of(LevelOfConfidence.HMRC200, LevelOfConfidence.MEDIUM_LEVEL))));
    }

    @Test
    void ShouldSerializeCorrectly() {
        var expectedJson =
                """
                [
                    {
                        "credentialTrustLevelCode": "C2",
                        "credentialTrustLevel": "MEDIUM_LEVEL",
                        "levelOfConfidenceCode": "P2",
                        "levelOfConfidence": "MEDIUM_LEVEL"
                    },
                    {
                        "credentialTrustLevelCode": "Cl.Cm",
                        "credentialTrustLevel": "MEDIUM_LEVEL",
                        "levelOfConfidenceCode": "PCL250",
                        "levelOfConfidence": "HMRC250"
                    },
                    {
                        "credentialTrustLevelCode": "Cl",
                        "credentialTrustLevel": "LOW_LEVEL",
                        "levelOfConfidenceCode": "",
                        "levelOfConfidence": "NONE"
                     }
                 ]
                 """;

        var actualJson = gson.toJson(VtrList.of(votP2C2, votPCL250ClCm, votCl));

        assertThat(
                JsonParser.parseString(actualJson),
                is(equalTo(JsonParser.parseString(expectedJson))));
    }

    @Test
    void ShouldDeserializeCorrectly() {
        var expectedVtrList = VtrList.of(votP2C2, votPCL250ClCm, votCl);

        var actualVtrList =
                gson.fromJson(
                        """
                [
                    {
                        "credentialTrustLevelCode": "C2",
                        "credentialTrustLevel": "MEDIUM_LEVEL",
                        "levelOfConfidenceCode": "P2",
                        "levelOfConfidence": "MEDIUM_LEVEL"
                    },
                    {
                        "credentialTrustLevelCode": "Cl.Cm",
                        "credentialTrustLevel": "MEDIUM_LEVEL",
                        "levelOfConfidenceCode": "PCL250",
                        "levelOfConfidence": "HMRC250"
                    },
                    {
                        "credentialTrustLevelCode": "Cl",
                        "credentialTrustLevel": "LOW_LEVEL",
                        "levelOfConfidenceCode": "",
                        "levelOfConfidence": "NONE"
                     }
                 ]
                 """,
                        VtrList.class);

        assertThat(expectedVtrList.getVtr().size(), is(equalTo(actualVtrList.getVtr().size())));
        for (int i = 0; i < expectedVtrList.getVtr().size(); i++) {
            assertThat(
                    expectedVtrList.getVtr().get(i).getCredentialTrustLevelCode(),
                    is(equalTo(actualVtrList.getVtr().get(i).getCredentialTrustLevelCode())));
            assertThat(
                    expectedVtrList.getVtr().get(i).getLevelOfConfidenceCode(),
                    is(equalTo(actualVtrList.getVtr().get(i).getLevelOfConfidenceCode())));
        }
    }
}

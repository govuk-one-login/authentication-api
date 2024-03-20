package uk.gov.di.orchestration.shared.entity;

import com.google.gson.Gson;
import com.google.gson.JsonParser;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.orchestration.shared.entity.vectoroftrust.CredentialTrustLevel;
import uk.gov.di.orchestration.shared.entity.vectoroftrust.CredentialTrustLevelCode;
import uk.gov.di.orchestration.shared.entity.vectoroftrust.LevelOfConfidence;
import uk.gov.di.orchestration.shared.entity.vectoroftrust.LevelOfConfidenceCode;
import uk.gov.di.orchestration.shared.entity.vectoroftrust.VectorOfTrust;

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

class VectorOfTrustTest {

    private static Gson gson;
    private static VectorOfTrust votCl;
    private static VectorOfTrust votC1;
    private static VectorOfTrust votClCm;
    private static VectorOfTrust votC2;
    private static VectorOfTrust votP0Cl;
    private static VectorOfTrust votP0C1;
    private static VectorOfTrust votP0ClCm;
    private static VectorOfTrust votP0C2;
    private static VectorOfTrust votP2ClCm;
    private static VectorOfTrust votP2C2;
    private static VectorOfTrust votPCL250C2;

    @BeforeAll
    static void Setup() {
        gson = new Gson();
        votCl = VectorOfTrust.of(CL);
        votC1 = VectorOfTrust.of(C1);
        votClCm = VectorOfTrust.of(CL_CM);
        votC2 = VectorOfTrust.of(C2);
        votP0Cl = VectorOfTrust.of(CL, P0);
        votP0C1 = VectorOfTrust.of(C1, P0);
        votP0ClCm = VectorOfTrust.of(CL_CM, P0);
        votP0C2 = VectorOfTrust.of(C2, P0);
        votP2ClCm = VectorOfTrust.of(CL_CM, P2);
        votP2C2 = VectorOfTrust.of(C2, P2);
        votPCL250C2 = VectorOfTrust.of(C2, PCL250);
    }

    @Test
    void ofReturnsCorrectVector() {
        var vot1 = VectorOfTrust.of(CL_CM);
        assertThat(vot1.getCredentialTrustLevelCode(), is(equalTo(CL_CM)));
        assertThat(vot1.getCredentialTrustLevel(), is(equalTo(CredentialTrustLevel.MEDIUM_LEVEL)));
        assertThat(vot1.getLevelOfConfidenceCode(), is(equalTo(EMPTY)));
        assertThat(vot1.getLevelOfConfidence(), is(equalTo(LevelOfConfidence.NONE)));

        var vot2 = VectorOfTrust.of(C2, P2);
        assertThat(vot2.getCredentialTrustLevelCode(), is(equalTo(C2)));
        assertThat(vot2.getCredentialTrustLevel(), is(equalTo(CredentialTrustLevel.MEDIUM_LEVEL)));
        assertThat(vot2.getLevelOfConfidenceCode(), is(equalTo(P2)));
        assertThat(vot2.getLevelOfConfidence(), is(equalTo(LevelOfConfidence.MEDIUM_LEVEL)));

        var vot3 = VectorOfTrust.of(CredentialTrustLevel.MEDIUM_LEVEL);
        assertThat(vot3.getCredentialTrustLevelCode(), is(equalTo(CL_CM)));
        assertThat(vot3.getCredentialTrustLevel(), is(equalTo(CredentialTrustLevel.MEDIUM_LEVEL)));
        assertThat(vot3.getLevelOfConfidenceCode(), is(equalTo(EMPTY)));
        assertThat(vot3.getLevelOfConfidence(), is(equalTo(LevelOfConfidence.NONE)));

        var vot4 = VectorOfTrust.of(CredentialTrustLevel.MEDIUM_LEVEL, LevelOfConfidence.HMRC200);
        assertThat(vot4.getCredentialTrustLevelCode(), is(equalTo(CL_CM)));
        assertThat(vot4.getCredentialTrustLevel(), is(equalTo(CredentialTrustLevel.MEDIUM_LEVEL)));
        assertThat(vot4.getLevelOfConfidenceCode(), is(equalTo(PCL200)));
        assertThat(vot4.getLevelOfConfidence(), is(equalTo(LevelOfConfidence.HMRC200)));
    }

    @ParameterizedTest
    @MethodSource("parseSuccessTestCases")
    void parseShouldReturnCorrectVectorOfTrust(String input, VectorOfTrust expectedVot) {
        var actualVot = VectorOfTrust.parse(input);
        MatcherAssert.assertThat(
                actualVot.getCredentialTrustLevelCode(),
                is(equalTo(expectedVot.getCredentialTrustLevelCode())));
        MatcherAssert.assertThat(
                actualVot.getCredentialTrustLevel(),
                is(equalTo(expectedVot.getCredentialTrustLevel())));
        MatcherAssert.assertThat(
                actualVot.getLevelOfConfidenceCode(),
                is(equalTo(expectedVot.getLevelOfConfidenceCode())));
        MatcherAssert.assertThat(
                actualVot.getLevelOfConfidence(), is(equalTo(expectedVot.getLevelOfConfidence())));
    }

    static Stream<Arguments> parseSuccessTestCases() {
        return Stream.of(
                arguments("Cl", votCl),
                arguments("Cl.Cm", votClCm),
                arguments("Cl.Cm.P2", votP2ClCm),
                arguments("Cm.P2.Cl", votP2ClCm), // note we support arbitrary ordering if ids
                arguments("PCL250.C2", votPCL250C2));
    }

    @ParameterizedTest
    @MethodSource("parseFailureTestCases")
    void parseShouldThrowWhenUnknownIdIsProvided(String invalid) {
        assertThrows(IllegalArgumentException.class, () -> VectorOfTrust.parse(invalid));
    }

    static Stream<Arguments> parseFailureTestCases() {
        return Stream.of(
                arguments(" "), // unexpected whitespace
                arguments(" Cl"), // ...
                arguments("Cl "), // ...
                arguments("CL"), // wrong case
                arguments("ClCm"), // bad formatting
                arguments("Cl Cm"), // ...
                arguments("Cl..P0"), // ...
                arguments("."), // ...
                arguments(".Cl"), // ...
                arguments("Cl."), // ...
                arguments("Clm"), // bad id
                arguments("HMRC200") // ...
                );
    }

    @ParameterizedTest
    @MethodSource("getCredentialTrustLevelCodeTestCases")
    void getCredentialTrustLevelCodeReturnsCorrectValues(
            VectorOfTrust vot, CredentialTrustLevelCode expectedCltCode) {
        assertThat(vot.getCredentialTrustLevelCode(), is(equalTo(expectedCltCode)));
    }

    static Stream<Arguments> getCredentialTrustLevelCodeTestCases() {
        return Stream.of(
                arguments(votCl, CL),
                arguments(votP0C2, C2),
                arguments(votP2ClCm, CL_CM),
                arguments(votPCL250C2, C2));
    }

    @ParameterizedTest
    @MethodSource("getLevelOfConfidenceCodeTestCases")
    void getLevelOfConfidenceCodeReturnsCorrectValues(
            VectorOfTrust vot, LevelOfConfidenceCode expectedLocCode) {
        assertThat(vot.getLevelOfConfidenceCode(), is(equalTo(expectedLocCode)));
    }

    static Stream<Arguments> getLevelOfConfidenceCodeTestCases() {
        return Stream.of(
                arguments(votCl, EMPTY),
                arguments(votP0C2, P0),
                arguments(votP2ClCm, P2),
                arguments(votPCL250C2, PCL250));
    }

    @ParameterizedTest
    @MethodSource("getCredentialTrustLevelTestCases")
    void getCredentialTrustLevelReturnsCorrectValues(
            VectorOfTrust vot, CredentialTrustLevel expectedCtl) {
        assertThat(vot.getCredentialTrustLevel(), is(equalTo(expectedCtl)));
    }

    static Stream<Arguments> getCredentialTrustLevelTestCases() {
        return Stream.of(
                arguments(votCl, CredentialTrustLevel.LOW_LEVEL),
                arguments(votP0C2, CredentialTrustLevel.MEDIUM_LEVEL),
                arguments(votP2ClCm, CredentialTrustLevel.MEDIUM_LEVEL),
                arguments(votPCL250C2, CredentialTrustLevel.MEDIUM_LEVEL));
    }

    @ParameterizedTest
    @MethodSource("getLevelOfConfidenceTestCases")
    void getLevelOfConfidenceReturnsCorrectValues(
            VectorOfTrust vot, LevelOfConfidence expectedLoc) {
        assertThat(vot.getLevelOfConfidence(), is(equalTo(expectedLoc)));
    }

    static Stream<Arguments> getLevelOfConfidenceTestCases() {
        return Stream.of(
                arguments(votCl, LevelOfConfidence.NONE),
                arguments(votP0C2, LevelOfConfidence.NONE),
                arguments(votP2ClCm, LevelOfConfidence.MEDIUM_LEVEL),
                arguments(votPCL250C2, LevelOfConfidence.HMRC250));
    }

    @ParameterizedTest
    @MethodSource("requiresIdentityTestCases")
    void requiresIdentityReturnsCorrectValues(VectorOfTrust vot, boolean expectedRequiresIdentity) {
        assertThat(vot.identityRequired(), is(equalTo(expectedRequiresIdentity)));
    }

    static Stream<Arguments> requiresIdentityTestCases() {
        return Stream.of(
                arguments(votCl, false),
                arguments(votP0C2, false),
                arguments(votP2ClCm, true),
                arguments(votP2C2, true));
    }

    @ParameterizedTest
    @MethodSource("requiresMfaTestCases")
    void requiresMfaReturnsCorrectValues(VectorOfTrust vot, boolean expectedRequiresMfa) {
        assertThat(vot.mfaRequired(), is(equalTo(expectedRequiresMfa)));
    }

    static Stream<Arguments> requiresMfaTestCases() {
        return Stream.of(
                arguments(votCl, false),
                arguments(votP0C2, true),
                arguments(votP2ClCm, true),
                arguments(votP2C2, true));
    }

    @ParameterizedTest
    @MethodSource("toStringTestCases")
    void toStringShouldReturnCorrectStringValue(VectorOfTrust input, String expected) {
        assertThat(input.toString(), is(equalTo(expected)));
    }

    static Stream<Arguments> toStringTestCases() {
        return Stream.of(
                arguments(votCl, "Cl"),
                arguments(votClCm, "Cl.Cm"),
                arguments(votP0Cl, "P0.Cl"),
                arguments(votP2ClCm, "P2.Cl.Cm"),
                arguments(votPCL250C2, "PCL250.C2"));
    }

    @ParameterizedTest
    @MethodSource("equalsAndHashCodeAnCompareToTestCases")
    void equalsAndHashCodeAndCompareToShouldBehaveCorrectly(
            VectorOfTrust vot1, VectorOfTrust vot2, int expectedCompareToSignum) {
        // test compareTo
        assertThat(
                Math.signum(vot1.compareTo(vot2)),
                is(equalTo(Math.signum(expectedCompareToSignum))));
        assertThat(
                Math.signum(vot2.compareTo(vot1)),
                is(equalTo(Math.signum(-expectedCompareToSignum))));

        var expectedEquals = expectedCompareToSignum == 0;

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
                // equivalent group 1
                arguments(votCl, votC1, 0),
                arguments(votCl, votP0Cl, 0),
                arguments(votCl, votP0C1, 0),
                // equivalent group 2
                arguments(votClCm, votC2, 0),
                arguments(votClCm, votP0ClCm, 0),
                arguments(votClCm, votP0C2, 0),
                // equivalent group 3
                arguments(votP2ClCm, votP2C2, 0),
                // different
                arguments(votP0C1, votP0C2, -1),
                arguments(votP2C2, votP0C2, 1),
                arguments(votP0C1, votP2C2, -1));
    }

    @ParameterizedTest
    @MethodSource("serializeTestCases")
    void ShouldSerializeCorrectly(VectorOfTrust vot, String expectedJson) {
        var actualJson = gson.toJson(vot);
        assertThat(
                JsonParser.parseString(actualJson),
                is(equalTo(JsonParser.parseString(expectedJson))));
    }

    static Stream<Arguments> serializeTestCases() {
        return Stream.of(
                arguments(
                        votP2C2,
                        """
                        {
                            "credentialTrustLevelCode": "C2",
                            "credentialTrustLevel": "MEDIUM_LEVEL",
                            "levelOfConfidenceCode": "P2",
                            "levelOfConfidence": "MEDIUM_LEVEL"
                        }
                        """),
                arguments(
                        votClCm,
                        """
                        {
                            "credentialTrustLevelCode": "Cl.Cm",
                            "credentialTrustLevel": "MEDIUM_LEVEL",
                            "levelOfConfidenceCode": "",
                            "levelOfConfidence": "NONE"
                        }
                        """),
                arguments(
                        votP0Cl,
                        """
                        {
                            "credentialTrustLevelCode": "Cl",
                            "credentialTrustLevel": "LOW_LEVEL",
                            "levelOfConfidenceCode": "P0",
                            "levelOfConfidence": "NONE"
                        }
                        """));
    }

    @ParameterizedTest
    @MethodSource("deserializeTestCases")
    public void ShouldDeserializeCorrectly(String json, VectorOfTrust expectedVot) {
        var actualVot = gson.fromJson(json, VectorOfTrust.class);

        assertThat(actualVot, is(equalTo(expectedVot)));
    }

    static Stream<Arguments> deserializeTestCases() {
        return Stream.of(
                arguments(
                        """
                        {
                            "credentialTrustLevelCode": "C2",
                            "credentialTrustLevel": "MEDIUM_LEVEL",
                            "levelOfConfidenceCode": "P2",
                            "levelOfConfidence": "MEDIUM_LEVEL"
                        }
                        """,
                        votP2C2),
                arguments(
                        """
                        {
                            "credentialTrustLevelCode": "Cl.Cm",
                            "credentialTrustLevel": "MEDIUM_LEVEL",
                            "levelOfConfidenceCode": "",
                            "levelOfConfidence": "NONE"
                        }
                        """,
                        votClCm),
                arguments(
                        """
                        {
                            "credentialTrustLevelCode": "Cl",
                            "credentialTrustLevel": "LOW_LEVEL",
                            "levelOfConfidenceCode": "P0",
                            "levelOfConfidence": "NONE"
                        }
                        """,
                        votP0Cl));
    }
}

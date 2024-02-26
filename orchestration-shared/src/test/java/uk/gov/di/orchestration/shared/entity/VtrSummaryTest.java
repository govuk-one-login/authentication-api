package uk.gov.di.orchestration.shared.entity;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.orchestration.shared.entity.vectoroftrust.VectorOfTrust;
import uk.gov.di.orchestration.shared.entity.vectoroftrust.VtrSummary;

import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.VotConstants.AUTH_LOW;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.VotConstants.AUTH_LOW_LEGACY;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.VotConstants.AUTH_MEDIUM;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.VotConstants.AUTH_MEDIUM_LEGACY;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.VotConstants.AUTH_VERY_HIGH;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.VotConstants.IDENT_HMRC200;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.VotConstants.IDENT_HMRC250;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.VotConstants.IDENT_LOW;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.VotConstants.IDENT_MEDIUM;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.VotConstants.IDENT_NONE;

public class VtrSummaryTest {

    private static VectorOfTrust votEmpty;
    private static VectorOfTrust votCl;
    private static VectorOfTrust votC1;
    private static VectorOfTrust votClCm;
    private static VectorOfTrust votC2;
    private static VectorOfTrust votClP0;
    private static VectorOfTrust votClCmP0;
    private static VectorOfTrust votP0;
    private static VectorOfTrust votClCmP2;
    private static VectorOfTrust votC2P2;
    private static VectorOfTrust votC4P2;
    private static VectorOfTrust votPCL250;
    private static VectorOfTrust votC2PCL200;
    private static VectorOfTrust votClCmPCL200;
    private static VectorOfTrust votC1P2;

    @BeforeAll
    public static void Setup()
    {
        votEmpty = VectorOfTrust.empty();
        votCl = VectorOfTrust.ofAuthComponent(AUTH_LOW_LEGACY);
        votC1 = VectorOfTrust.ofAuthComponent(AUTH_LOW);
        votClCm = VectorOfTrust.ofAuthComponent(AUTH_MEDIUM_LEGACY);
        votC2 = VectorOfTrust.ofAuthComponent(AUTH_MEDIUM);
        votClP0 = new VectorOfTrust(AUTH_LOW_LEGACY, IDENT_LOW);
        votClCmP0 = new VectorOfTrust(AUTH_MEDIUM_LEGACY, IDENT_LOW);
        votP0 = VectorOfTrust.ofIdentComponent(IDENT_NONE);
        votClCmP2 = new VectorOfTrust(AUTH_MEDIUM_LEGACY, IDENT_MEDIUM);
        votC2P2 = new VectorOfTrust(AUTH_MEDIUM, IDENT_MEDIUM);
        votC4P2 = new VectorOfTrust(AUTH_VERY_HIGH, IDENT_MEDIUM);
        votPCL250 = VectorOfTrust.ofIdentComponent(IDENT_HMRC250);
        votC2PCL200 = new VectorOfTrust(AUTH_MEDIUM, IDENT_HMRC200);
        votClCmPCL200 = new VectorOfTrust(AUTH_MEDIUM_LEGACY, IDENT_HMRC200);
        votC1P2 = new VectorOfTrust(AUTH_LOW, IDENT_MEDIUM);
    }

    @ParameterizedTest
    @MethodSource("generateSummarySuccessTestCases")
    public void generateFromAuthRequestAttributeReturnCorrectVtrRequestSummary(List<String> vtr,
                                                                               VtrSummary expectedSummary) {
        var actualSummary = VtrSummary.generateFromAuthRequestAttribute(vtr);

        assertThat(actualSummary.vtr().size(), is(equalTo(expectedSummary.vtr().size())));

        for(int i = 0; i < expectedSummary.vtr().size(); i++) {
            assertIdenticalComponents(actualSummary.vtr().get(i), actualSummary.vtr().get(i));
        }

        assertIdenticalComponents(actualSummary.chosenVot(), expectedSummary.chosenVot());
        assertIdenticalComponents(actualSummary.effectiveVot(), expectedSummary.effectiveVot());
    }

    private static void assertIdenticalComponents(VectorOfTrust actualVot, VectorOfTrust expectedVot) {
        assertThat(actualVot.getAuthComponent(), is(equalTo(expectedVot.getAuthComponent())));
        assertThat(actualVot.getIdentComponent(), is(equalTo(expectedVot.getIdentComponent())));
    }

    public static Stream<Arguments> generateSummarySuccessTestCases() {
        return Stream.of(
                arguments(null,
                          new VtrSummary(Collections.emptyList(),
                                         votEmpty,
                                         votClCmP0)),
                arguments(Collections.emptyList(),
                          new VtrSummary(Collections.emptyList(),
                                         votEmpty,
                                         votClCmP0)),
                arguments(List.of(""),
                          new VtrSummary(List.of(votEmpty),
                                         votEmpty,
                                         votClCmP0)),
                arguments(List.of("[\"C2\"]"),
                          new VtrSummary(List.of(votC2),
                                        votC2,
                                        votClCmP0)),
                arguments(List.of("[\"P0\"]"),
                          new VtrSummary(List.of(votP0),
                                         votP0,
                                         votClCmP0)),
                arguments(List.of("\"C1\",\"C2\",\"C2\"]"),
                          new VtrSummary(List.of(votC1, votC2, votC2),
                                         votC1,
                                         votClP0)),
                arguments(List.of("\"C2\",\"Cl.P0.Cm\"]"),
                          new VtrSummary(List.of(votC2, votClCmP0),
                                         votC2,
                                         votClCmP0)),
                arguments(List.of("\"Cl.P0.Cm\", \"C2\"]"),
                          new VtrSummary(List.of(votClCmP0, votC2),
                                         votClCmP0,
                                         votClCmP0)),
                arguments(List.of("[\"\",\"P0\",\"C2\",\"C1\",\"Cl.Cm\",\"Cl\"]"),
                          new VtrSummary(List.of(votEmpty, votP0, votC2, votCl, votClCm, votC1),
                                         votC1,
                                         votClP0)),
                arguments(List.of("[\"P2.C4\",\"C2.P2\"]"),
                          new VtrSummary(List.of(votC4P2, votC2P2),
                                         votC2P2,
                                         votClCmP2)),
                arguments(List.of("[\"PCL250\",\"PCL200.C2\"]"),
                          new VtrSummary(List.of(votPCL250, votC2PCL200),
                                         votC2PCL200,
                                         votClCmPCL200))
        );
    }

    @ParameterizedTest
    @MethodSource("generateSummaryFailureTestCases")
    public void generateFromAuthRequestAttributeThrowsOnInvalidVtr(List<String> vtr, String expectedErrorMessage) {
        assertThrows(IllegalArgumentException.class,
                     () -> VtrSummary.generateFromAuthRequestAttribute(vtr),
                     expectedErrorMessage);
    }

    public static Stream<Arguments> generateSummaryFailureTestCases() {
        return Stream.of(
                arguments(List.of("C2", "Cl.P0.Cm"),
                          "Expected VTR to have single entry."),
                arguments(List.of("(CL|CM)"),
                          "Invalid VTR attribute.")\
        );
    }
}

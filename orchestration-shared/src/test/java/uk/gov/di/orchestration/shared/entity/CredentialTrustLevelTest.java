package uk.gov.di.orchestration.shared.entity;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.orchestration.shared.entity.vectoroftrust.CredentialTrustLevel;
import uk.gov.di.orchestration.shared.entity.vectoroftrust.CredentialTrustLevelCode;
import uk.gov.di.orchestration.shared.entity.vectoroftrust.CredentialTrustLevelId;

import java.util.EnumSet;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.lessThan;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.CredentialTrustLevel.HIGH_LEVEL;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.CredentialTrustLevel.LOW_LEVEL;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.CredentialTrustLevel.MEDIUM_LEVEL;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.CredentialTrustLevel.VERY_HIGH_LEVEL;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.CredentialTrustLevelCode.C1;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.CredentialTrustLevelCode.C2;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.CredentialTrustLevelCode.C3;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.CredentialTrustLevelCode.C4;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.CredentialTrustLevelCode.CL;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.CredentialTrustLevelCode.CL_CM;

class CredentialTrustLevelTest {

    @Test
    void valuesShouldBeComparable() {
        assertThat(LOW_LEVEL, lessThan(MEDIUM_LEVEL));
    }

    @ParameterizedTest
    @MethodSource("ofSuccessTestCases")
    void ofShouldReturnCorrectValue(
            CredentialTrustLevelCode ctlCode, CredentialTrustLevel expectedCtl) {
        assertThat(CredentialTrustLevel.of(ctlCode), is(equalTo(expectedCtl)));
    }

    static Stream<Arguments> ofSuccessTestCases() {
        return Stream.of(
                arguments(CL, LOW_LEVEL),
                arguments(C1, LOW_LEVEL),
                arguments(CL_CM, MEDIUM_LEVEL),
                arguments(C2, MEDIUM_LEVEL),
                arguments(C3, HIGH_LEVEL),
                arguments(C4, VERY_HIGH_LEVEL));
    }

    @Test
    void ofShouldThrowIfInvalidCodeProvided() {
        var invalidCode = new CredentialTrustLevelCode(EnumSet.of(CredentialTrustLevelId.CM));
        assertThrows(IllegalArgumentException.class, () -> CredentialTrustLevel.of(invalidCode));
    }

    @ParameterizedTest
    @MethodSource("getDefaultCodeTestCases")
    void getDefaultCodeShouldReturnCorrectValue(
            CredentialTrustLevel ctl, CredentialTrustLevelCode expectedAuthComponent) {
        assertThat(ctl.getDefaultCode(), is(equalTo(expectedAuthComponent)));
    }

    static Stream<Arguments> getDefaultCodeTestCases() {
        return Stream.of(
                arguments(LOW_LEVEL, CL),
                arguments(MEDIUM_LEVEL, CL_CM),
                arguments(HIGH_LEVEL, C3),
                arguments(VERY_HIGH_LEVEL, C4));
    }

    @ParameterizedTest
    @MethodSource("isSupportedTestCases")
    void isSupportedShouldReturnCorrectValue(
            CredentialTrustLevel ctl, boolean expectedIsSupported) {
        assertThat(ctl.isSupported(), is(equalTo(expectedIsSupported)));
    }

    static Stream<Arguments> isSupportedTestCases() {
        return Stream.of(
                arguments(LOW_LEVEL, true),
                arguments(MEDIUM_LEVEL, true),
                arguments(HIGH_LEVEL, false),
                arguments(VERY_HIGH_LEVEL, false));
    }
}

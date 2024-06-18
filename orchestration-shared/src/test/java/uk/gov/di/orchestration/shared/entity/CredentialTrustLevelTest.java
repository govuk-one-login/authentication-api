package uk.gov.di.orchestration.shared.entity;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.EnumSet;
import java.util.Set;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.lessThan;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static uk.gov.di.orchestration.shared.entity.CredentialTrustLevel.LOW_LEVEL;
import static uk.gov.di.orchestration.shared.entity.CredentialTrustLevel.MEDIUM_LEVEL;
import static uk.gov.di.orchestration.shared.entity.CredentialTrustLevelCode.C1;
import static uk.gov.di.orchestration.shared.entity.CredentialTrustLevelCode.C2;
import static uk.gov.di.orchestration.shared.entity.CredentialTrustLevelCode.CL;
import static uk.gov.di.orchestration.shared.entity.CredentialTrustLevelCode.CL_CM;

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
        return Stream.of(arguments(CL, LOW_LEVEL), arguments(CL_CM, MEDIUM_LEVEL));
    }

    @Test
    void ofShouldThrowIfInvalidCodeProvided() {
        var invalidCode = new CredentialTrustLevelCode(EnumSet.of(CredentialTrustLevelId.CM));
        assertThrows(IllegalArgumentException.class, () -> CredentialTrustLevel.of(invalidCode));
    }

    @ParameterizedTest
    @MethodSource("getDefaultCodeTestCases")
    void getDefaultCodeShouldReturnCorrectValue(
            CredentialTrustLevel ctl, CredentialTrustLevelCode expectedCtlCode) {
        assertThat(ctl.getDefaultCode(), is(equalTo(expectedCtlCode)));
    }

    static Stream<Arguments> getDefaultCodeTestCases() {
        return Stream.of(arguments(LOW_LEVEL, CL), arguments(MEDIUM_LEVEL, CL_CM));
    }

    @ParameterizedTest
    @MethodSource("getAllCodesTestCases")
    void getAllCodesShouldReturnCorrectValue(
            CredentialTrustLevel ctl, Set<CredentialTrustLevelCode> expectedCtlCodes) {
        assertThat(ctl.getAllCodes(), is(equalTo(expectedCtlCodes)));
    }

    static Stream<Arguments> getAllCodesTestCases() {
        return Stream.of(
                arguments(LOW_LEVEL, Set.of(CL, C1)), arguments(MEDIUM_LEVEL, Set.of(CL_CM, C2)));
    }
}

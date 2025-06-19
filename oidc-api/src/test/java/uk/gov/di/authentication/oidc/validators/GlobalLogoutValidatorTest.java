package uk.gov.di.authentication.oidc.validators;

import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.oidc.entity.GlobalLogoutMessage;
import uk.gov.di.authentication.oidc.exceptions.GlobalLogoutValidationException;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static uk.gov.di.authentication.oidc.validators.GlobalLogoutValidator.validate;

public class GlobalLogoutValidatorTest {

    private static Stream<Arguments> invalidMessages() {
        return Stream.of(
                Arguments.of(
                        Named.of(
                                "clientId is empty string",
                                new GlobalLogoutMessage("", "a", "a", "a", "a", "a", "a"))),
                Arguments.of(
                        Named.of(
                                "eventId is empty string",
                                new GlobalLogoutMessage("a", "", "a", "a", "a", "a", "a"))),
                Arguments.of(
                        Named.of(
                                "sessionId is empty string",
                                new GlobalLogoutMessage("a", "a", "", "a", "a", "a", "a"))),
                Arguments.of(
                        Named.of(
                                "clientSessionId is empty string",
                                new GlobalLogoutMessage("a", "a", "a", "", "a", "a", "a"))),
                Arguments.of(
                        Named.of(
                                "internalCommonSubjectId is empty string",
                                new GlobalLogoutMessage("a", "a", "a", "a", "", "a", "a"))),
                Arguments.of(
                        Named.of(
                                "persistentSessionId is empty string",
                                new GlobalLogoutMessage("a", "a", "a", "a", "a", "", "a"))),
                Arguments.of(
                        Named.of(
                                "ipAddress is empty string",
                                new GlobalLogoutMessage("a", "a", "a", "a", "a", "a", ""))));
    }

    @ParameterizedTest
    @MethodSource("invalidMessages")
    public void shouldThrowExceptionWhenValidationFails(GlobalLogoutMessage invalidMessage) {
        assertThrows(GlobalLogoutValidationException.class, () -> validate(invalidMessage));
    }

    @Test
    void shouldNotThrowWhenValidationIsSuccessful() {
        var validMessage = new GlobalLogoutMessage("a", "a", "a", "a", "a", "a", "a");
        assertDoesNotThrow(() -> validate(validMessage));
    }
}

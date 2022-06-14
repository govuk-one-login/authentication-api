package uk.gov.di.authentication.shared.validation;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.services.CommonPasswordsService;

import java.util.Optional;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class PasswordValidatorTest {
    PasswordValidator validator;

    @BeforeEach
    public void setUp() {
        CommonPasswordsService mockDynamoService = mock(CommonPasswordsService.class);
        when(mockDynamoService.isCommonPassword("TestCommonPassword1")).thenReturn(true);
        this.validator = new PasswordValidator(mockDynamoService);
    }

    private static Stream<Arguments> invalidPasswords() {
        return Stream.of(
                Arguments.of("", ErrorResponse.ERROR_1005),
                Arguments.of(null, ErrorResponse.ERROR_1005),
                Arguments.of("passw0r", ErrorResponse.ERROR_1006),
                Arguments.of("passwordpasswordpassword", ErrorResponse.ERROR_1007),
                Arguments.of("TestCommonPassword1", ErrorResponse.ERROR_1040));
    }

    @ParameterizedTest
    @MethodSource("invalidPasswords")
    void shouldRejectInvalidPasswords(String password, ErrorResponse expectedResponse) {
        assertEquals(Optional.of(expectedResponse), validator.validate(password));
    }

    private static Stream<String> validPasswords() {
        return Stream.of(
                "+pa?55worD",
                "computer-1",
                "passsssssssssssswwwwoooordddd-2",
                "TestCommonPassword2");
    }

    @ParameterizedTest
    @MethodSource("validPasswords")
    void shouldAcceptValidPassword(String password) {
        assertEquals(Optional.empty(), validator.validate(password));
    }
}

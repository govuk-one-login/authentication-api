package uk.gov.di.authentication.entity;

import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.CodeRequestType;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertTrue;

class CodeRequestTypeTest {

    @Test
    void testForZddDeployment() {
        var codeDefinedEnumValues =
                Arrays.stream(CodeRequestType.values())
                        .map(Enum::name)
                        .collect(Collectors.joining());
        var staticDefinedEnumValues =
                List.of(
                        "EMAIL_REGISTRATION",
                        "EMAIL_ACCOUNT_RECOVERY",
                        "EMAIL_PASSWORD_RESET",
                        "MFA_ACCOUNT_RECOVERY",
                        "MFA_PW_RESET_MFA",
                        "MFA_REGISTRATION",
                        "MFA_SIGN_IN",
                        "MFA_REAUTHENTICATION");

        staticDefinedEnumValues.forEach(
                v ->
                        assertTrue(
                                codeDefinedEnumValues.contains(v),
                                String.format(
                                        "%s removed from CodeRequestType. Ensure this change is ZDD compatible",
                                        v)));
    }
}

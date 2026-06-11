package uk.gov.di.authentication.entity;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.shared.entity.AuthSessionItem.AccountState;
import uk.gov.di.authentication.shared.entity.AuthSessionItem.ResetMfaState;
import uk.gov.di.authentication.shared.entity.AuthSessionItem.ResetPasswordState;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;

import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ExternalTICFCRIRequestTest {
    private static Stream<Arguments> ticfParametersSource() {
        return Stream.of(
                // Testing authenticated combinations
                Arguments.of(
                        new InternalTICFCRIRequest(
                                "test-sub",
                                List.of("Cl.Cm"),
                                "test-journey-id",
                                true,
                                AccountState.EXISTING,
                                ResetPasswordState.NONE,
                                ResetMfaState.NONE,
                                MFAMethodType.NONE,
                                false),
                        new ExternalTICFCRIRequest(
                                "test-sub",
                                List.of("Cl.Cm"),
                                "test-journey-id",
                                "Y",
                                null,
                                null,
                                null,
                                null,
                                null)),
                Arguments.of(
                        new InternalTICFCRIRequest(
                                "test-sub",
                                List.of("Cl.Cm"),
                                "test-journey-id",
                                false,
                                AccountState.EXISTING,
                                ResetPasswordState.NONE,
                                ResetMfaState.NONE,
                                MFAMethodType.NONE,
                                false),
                        new ExternalTICFCRIRequest(
                                "test-sub",
                                List.of("Cl.Cm"),
                                "test-journey-id",
                                "N",
                                null,
                                null,
                                null,
                                null,
                                null)),

                // Testing initial registration combinations
                Arguments.of(
                        new InternalTICFCRIRequest(
                                "test-sub",
                                List.of("Cl.Cm"),
                                "test-journey-id",
                                true,
                                AccountState.NEW,
                                ResetPasswordState.NONE,
                                ResetMfaState.NONE,
                                MFAMethodType.NONE,
                                false),
                        new ExternalTICFCRIRequest(
                                "test-sub",
                                List.of("Cl.Cm"),
                                "test-journey-id",
                                "Y",
                                "Y",
                                null,
                                null,
                                null,
                                null)),
                Arguments.of(
                        new InternalTICFCRIRequest(
                                "test-sub",
                                List.of("Cl.Cm"),
                                "test-journey-id",
                                false,
                                AccountState.NEW,
                                ResetPasswordState.NONE,
                                ResetMfaState.NONE,
                                MFAMethodType.NONE,
                                false),
                        new ExternalTICFCRIRequest(
                                "test-sub",
                                List.of("Cl.Cm"),
                                "test-journey-id",
                                "N",
                                "Y",
                                null,
                                null,
                                null,
                                null)),
                // Testing password reset combinations
                Arguments.of(
                        new InternalTICFCRIRequest(
                                "test-sub",
                                List.of("Cl.Cm"),
                                "test-journey-id",
                                true,
                                AccountState.EXISTING,
                                ResetPasswordState.SUCCEEDED,
                                ResetMfaState.NONE,
                                MFAMethodType.NONE,
                                false),
                        new ExternalTICFCRIRequest(
                                "test-sub",
                                List.of("Cl.Cm"),
                                "test-journey-id",
                                "Y",
                                null,
                                "Y",
                                null,
                                null,
                                null)),
                Arguments.of(
                        new InternalTICFCRIRequest(
                                "test-sub",
                                List.of("Cl.Cm"),
                                "test-journey-id",
                                false,
                                AccountState.EXISTING,
                                ResetPasswordState.ATTEMPTED,
                                ResetMfaState.NONE,
                                MFAMethodType.NONE,
                                false),
                        new ExternalTICFCRIRequest(
                                "test-sub",
                                List.of("Cl.Cm"),
                                "test-journey-id",
                                "N",
                                null,
                                "Y",
                                null,
                                null,
                                null)),
                Arguments.of(
                        new InternalTICFCRIRequest(
                                "test-sub",
                                List.of("Cl.Cm"),
                                "test-journey-id",
                                true,
                                AccountState.EXISTING,
                                ResetPasswordState.ATTEMPTED,
                                ResetMfaState.NONE,
                                MFAMethodType.NONE,
                                false),
                        new ExternalTICFCRIRequest(
                                "test-sub",
                                List.of("Cl.Cm"),
                                "test-journey-id",
                                "Y",
                                null,
                                null,
                                null,
                                null,
                                null)),
                // Testing mfa reset combinations
                Arguments.of(
                        new InternalTICFCRIRequest(
                                "test-sub",
                                List.of("Cl.Cm"),
                                "test-journey-id",
                                true,
                                AccountState.EXISTING,
                                ResetPasswordState.NONE,
                                ResetMfaState.SUCCEEDED,
                                MFAMethodType.NONE,
                                false),
                        new ExternalTICFCRIRequest(
                                "test-sub",
                                List.of("Cl.Cm"),
                                "test-journey-id",
                                "Y",
                                null,
                                null,
                                "Y",
                                null,
                                null)),
                Arguments.of(
                        new InternalTICFCRIRequest(
                                "test-sub",
                                List.of("Cl.Cm"),
                                "test-journey-id",
                                true,
                                AccountState.EXISTING,
                                ResetPasswordState.NONE,
                                ResetMfaState.ATTEMPTED,
                                MFAMethodType.NONE,
                                false),
                        new ExternalTICFCRIRequest(
                                "test-sub",
                                List.of("Cl.Cm"),
                                "test-journey-id",
                                "Y",
                                null,
                                null,
                                null,
                                null,
                                null)),
                Arguments.of(
                        new InternalTICFCRIRequest(
                                "test-sub",
                                List.of("Cl.Cm"),
                                "test-journey-id",
                                false,
                                AccountState.EXISTING,
                                ResetPasswordState.NONE,
                                ResetMfaState.ATTEMPTED,
                                MFAMethodType.NONE,
                                false),
                        new ExternalTICFCRIRequest(
                                "test-sub",
                                List.of("Cl.Cm"),
                                "test-journey-id",
                                "N",
                                null,
                                null,
                                "Y",
                                null,
                                null)),

                // Testing mfa method combinations
                Arguments.of(
                        new InternalTICFCRIRequest(
                                "test-sub",
                                List.of("Cl.Cm"),
                                "test-journey-id",
                                true,
                                AccountState.EXISTING,
                                ResetPasswordState.NONE,
                                ResetMfaState.NONE,
                                MFAMethodType.NONE,
                                false),
                        new ExternalTICFCRIRequest(
                                "test-sub",
                                List.of("Cl.Cm"),
                                "test-journey-id",
                                "Y",
                                null,
                                null,
                                null,
                                null,
                                null)),
                Arguments.of(
                        new InternalTICFCRIRequest(
                                "test-sub",
                                List.of("Cl.Cm"),
                                "test-journey-id",
                                true,
                                AccountState.EXISTING,
                                ResetPasswordState.ATTEMPTED,
                                ResetMfaState.NONE,
                                MFAMethodType.EMAIL,
                                false),
                        new ExternalTICFCRIRequest(
                                "test-sub",
                                List.of("Cl.Cm"),
                                "test-journey-id",
                                "Y",
                                null,
                                null,
                                null,
                                null,
                                null)),
                Arguments.of(
                        new InternalTICFCRIRequest(
                                "test-sub",
                                List.of("Cl.Cm"),
                                "test-journey-id",
                                true,
                                AccountState.EXISTING,
                                ResetPasswordState.ATTEMPTED,
                                ResetMfaState.NONE,
                                MFAMethodType.SMS,
                                false),
                        new ExternalTICFCRIRequest(
                                "test-sub",
                                List.of("Cl.Cm"),
                                "test-journey-id",
                                "Y",
                                null,
                                null,
                                null,
                                List.of("SMS"),
                                null)),
                Arguments.of(
                        new InternalTICFCRIRequest(
                                "test-sub",
                                List.of("Cl.Cm"),
                                "test-journey-id",
                                true,
                                AccountState.EXISTING,
                                ResetPasswordState.ATTEMPTED,
                                ResetMfaState.NONE,
                                MFAMethodType.AUTH_APP,
                                false),
                        new ExternalTICFCRIRequest(
                                "test-sub",
                                List.of("Cl.Cm"),
                                "test-journey-id",
                                "Y",
                                null,
                                null,
                                null,
                                List.of("AUTH_APP"),
                                null)),

                // Testing passkey combinations
                Arguments.of(
                        new InternalTICFCRIRequest(
                                "test-sub",
                                List.of("Cl.Cm"),
                                "test-journey-id",
                                true,
                                AccountState.EXISTING,
                                ResetPasswordState.NONE,
                                ResetMfaState.NONE,
                                MFAMethodType.NONE,
                                false),
                        new ExternalTICFCRIRequest(
                                "test-sub",
                                List.of("Cl.Cm"),
                                "test-journey-id",
                                "Y",
                                null,
                                null,
                                null,
                                null,
                                null)),
                Arguments.of(
                        new InternalTICFCRIRequest(
                                "test-sub",
                                List.of("Cl.Cm"),
                                "test-journey-id",
                                true,
                                AccountState.EXISTING,
                                ResetPasswordState.NONE,
                                ResetMfaState.NONE,
                                MFAMethodType.NONE,
                                true),
                        new ExternalTICFCRIRequest(
                                "test-sub",
                                List.of("Cl.Cm"),
                                "test-journey-id",
                                "Y",
                                null,
                                null,
                                null,
                                null,
                                "Y")));
    }

    @ParameterizedTest
    @MethodSource("ticfParametersSource")
    void shouldCorrectlyBeConstructedFromInternalRequest(
            InternalTICFCRIRequest provided, ExternalTICFCRIRequest expected) {
        assertEquals(expected, ExternalTICFCRIRequest.fromInternalRequest(provided, true));
    }

    @Test
    void shouldNotSendPasskeyIfPasskeysNotSupported() {
        var userSignedInWithPasskeyInternalTicfRequest =
                new InternalTICFCRIRequest(
                        "test-sub",
                        List.of("Cl.Cm"),
                        "test-journey-id",
                        true,
                        AccountState.EXISTING,
                        ResetPasswordState.NONE,
                        ResetMfaState.NONE,
                        MFAMethodType.NONE,
                        true);

        var expectedExternalTicfCriRequest =
                new ExternalTICFCRIRequest(
                        "test-sub",
                        List.of("Cl.Cm"),
                        "test-journey-id",
                        "Y",
                        null,
                        null,
                        null,
                        null,
                        null);

        assertEquals(
                ExternalTICFCRIRequest.fromInternalRequest(
                        userSignedInWithPasskeyInternalTicfRequest, false),
                expectedExternalTicfCriRequest);
    }
}

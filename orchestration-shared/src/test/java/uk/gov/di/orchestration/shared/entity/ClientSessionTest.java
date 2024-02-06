package uk.gov.di.orchestration.shared.entity;

import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.net.URI;
import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class ClientSessionTest {

    private static final ClientID CLIENT_ID = new ClientID();
    private static final URI REDIRECT_URI = URI.create("test-uri");
    private static final String CLIENT_NAME = "some-client-name";

    @ParameterizedTest
    @MethodSource("lowestCtrTestCases")
    void shouldCorrectlyFindVtrWithLowestCredentialTrustLevelFromList(
            List<VectorOfTrust> vtrList, CredentialTrustLevel expectedCtl) {

        ClientSession clientSession =
                new ClientSession(
                        generateAuthRequest().toParameters(),
                        LocalDateTime.now(),
                        vtrList,
                        CLIENT_NAME);

        var lowestVtr = VectorOfTrust.getLowestCredentialTrustLevel(clientSession.getVtrList());

        assertThat(lowestVtr.getValue(), equalTo(expectedCtl.getValue()));
    }

    @ParameterizedTest
    @MethodSource("locsCssTestCases")
    void shouldCorrectlyCreateVtrLevelsOfConfidenceAsCommaSeparatedString(
            List<VectorOfTrust> vtrList, String expectedCss) {

        ClientSession clientSession =
                new ClientSession(
                        generateAuthRequest().toParameters(),
                        LocalDateTime.now(),
                        vtrList,
                        CLIENT_NAME);

        var css = clientSession.getVtrLocsAsCommaSeparatedString();

        assertThat(css, equalTo(expectedCss));
    }

    @Test
    void shouldThrowExceptionForEmptyVtrList() {
        ClientSession clientSession =
                new ClientSession(
                        generateAuthRequest().toParameters(),
                        LocalDateTime.now(),
                        Collections.emptyList(),
                        CLIENT_NAME);

        IllegalArgumentException exception =
                assertThrows(
                        IllegalArgumentException.class,
                        () ->
                                VectorOfTrust.getLowestCredentialTrustLevel(
                                        clientSession.getVtrList()));

        assertEquals("Invalid VTR attribute", exception.getMessage());
    }

    @Test
    void shouldReturnEmptyStringForEmptyVtrList() {
        ClientSession clientSession =
                new ClientSession(
                        generateAuthRequest().toParameters(),
                        LocalDateTime.now(),
                        Collections.emptyList(),
                        CLIENT_NAME);

        assertEquals("", clientSession.getVtrLocsAsCommaSeparatedString());
    }

    private static Stream<Arguments> lowestCtrTestCases() {
        return Stream.of(
                arguments(
                        List.of(
                                VectorOfTrust.of(
                                        CredentialTrustLevel.LOW_LEVEL,
                                        LevelOfConfidence.getDefault()),
                                VectorOfTrust.of(
                                        CredentialTrustLevel.MEDIUM_LEVEL,
                                        LevelOfConfidence.getDefault())),
                        CredentialTrustLevel.LOW_LEVEL),
                arguments(
                        List.of(
                                VectorOfTrust.of(
                                        CredentialTrustLevel.LOW_LEVEL,
                                        LevelOfConfidence.getDefault()),
                                VectorOfTrust.of(
                                        CredentialTrustLevel.LOW_LEVEL,
                                        LevelOfConfidence.getDefault())),
                        CredentialTrustLevel.LOW_LEVEL),
                arguments(
                        List.of(
                                VectorOfTrust.of(
                                        CredentialTrustLevel.MEDIUM_LEVEL,
                                        LevelOfConfidence.getDefault()),
                                VectorOfTrust.of(
                                        CredentialTrustLevel.MEDIUM_LEVEL,
                                        LevelOfConfidence.getDefault())),
                        CredentialTrustLevel.MEDIUM_LEVEL),
                arguments(
                        List.of(
                                VectorOfTrust.of(
                                        CredentialTrustLevel.MEDIUM_LEVEL,
                                        LevelOfConfidence.getDefault()),
                                VectorOfTrust.of(
                                        CredentialTrustLevel.LOW_LEVEL,
                                        LevelOfConfidence.getDefault()),
                                VectorOfTrust.of(
                                        CredentialTrustLevel.MEDIUM_LEVEL,
                                        LevelOfConfidence.getDefault()),
                                VectorOfTrust.of(
                                        CredentialTrustLevel.MEDIUM_LEVEL,
                                        LevelOfConfidence.getDefault())),
                        CredentialTrustLevel.LOW_LEVEL),
                arguments(
                        List.of(
                                VectorOfTrust.of(
                                        CredentialTrustLevel.MEDIUM_LEVEL,
                                        LevelOfConfidence.getDefault()),
                                VectorOfTrust.of(
                                        CredentialTrustLevel.LOW_LEVEL,
                                        LevelOfConfidence.getDefault()),
                                VectorOfTrust.of(
                                        CredentialTrustLevel.LOW_LEVEL,
                                        LevelOfConfidence.getDefault()),
                                VectorOfTrust.of(
                                        CredentialTrustLevel.LOW_LEVEL,
                                        LevelOfConfidence.getDefault())),
                        CredentialTrustLevel.LOW_LEVEL));
    }

    private static Stream<Arguments> locsCssTestCases() {
        return Stream.of(
                arguments(
                        List.of(
                                VectorOfTrust.of(
                                        CredentialTrustLevel.getDefault(),
                                        LevelOfConfidence.HIGH_LEVEL)),
                        "P3"),
                arguments(
                        List.of(
                                VectorOfTrust.of(
                                        CredentialTrustLevel.getDefault(),
                                        LevelOfConfidence.getDefault()),
                                VectorOfTrust.of(
                                        CredentialTrustLevel.getDefault(),
                                        LevelOfConfidence.getDefault())),
                        "P2,P2"),
                arguments(
                        List.of(
                                VectorOfTrust.of(
                                        CredentialTrustLevel.getDefault(),
                                        LevelOfConfidence.VERY_HIGH_LEVEL),
                                VectorOfTrust.of(
                                        CredentialTrustLevel.getDefault(),
                                        LevelOfConfidence.LOW_LEVEL),
                                VectorOfTrust.of(
                                        CredentialTrustLevel.getDefault(),
                                        LevelOfConfidence.MEDIUM_LEVEL),
                                VectorOfTrust.of(
                                        CredentialTrustLevel.getDefault(),
                                        LevelOfConfidence.LOW_LEVEL)),
                        "P1,P1,P2,P4"));
    }

    private static AuthenticationRequest generateAuthRequest() {
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        State state = new State();
        Scope scope = new Scope();
        Nonce nonce = new Nonce();
        scope.add(OIDCScopeValue.OPENID);
        scope.add("phone");
        scope.add("email");
        return new AuthenticationRequest.Builder(responseType, scope, CLIENT_ID, REDIRECT_URI)
                .state(state)
                .nonce(nonce)
                .build();
    }
}

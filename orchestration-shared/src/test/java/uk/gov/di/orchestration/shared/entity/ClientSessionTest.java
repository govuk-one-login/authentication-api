package uk.gov.di.orchestration.shared.entity;

import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.orchestration.shared.entity.vectoroftrust.CredentialTrustLevel;
import uk.gov.di.orchestration.shared.entity.vectoroftrust.LevelOfConfidence;
import uk.gov.di.orchestration.shared.entity.vectoroftrust.VectorOfTrust;
import uk.gov.di.orchestration.shared.entity.vectoroftrust.VtrList;

import java.net.URI;
import java.time.LocalDateTime;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class ClientSessionTest {

    private static final ClientID CLIENT_ID = new ClientID();
    private static final URI REDIRECT_URI = URI.create("test-uri");
    private static final String CLIENT_NAME = "some-client-name";

    @ParameterizedTest
    @MethodSource("lowestCtrTestCases")
    void shouldCorrectlyFindVtrWithLowestCredentialTrustLevelFromList(
            VtrList vtrList, CredentialTrustLevel expectedCtl) {

        ClientSession clientSession =
                new ClientSession(
                        generateAuthRequest().toParameters(),
                        LocalDateTime.now(),
                        vtrList,
                        CLIENT_NAME);

        var actualCtl = clientSession.getVtrList().getSelectedCredentialTrustLevel();

        assertThat(actualCtl, equalTo(expectedCtl));
    }

    @ParameterizedTest
    @MethodSource("locsCssTestCases")
    void shouldCorrectlyCreateVtrLevelsOfConfidenceAsCommaSeparatedString(
            VtrList vtrList, String expectedCss) {

        ClientSession clientSession =
                new ClientSession(
                        generateAuthRequest().toParameters(),
                        LocalDateTime.now(),
                        vtrList,
                        CLIENT_NAME);

        var css = clientSession.getVtrLocsAsCommaSeparatedString();

        assertThat(css, equalTo(expectedCss));
    }

    private static Stream<Arguments> lowestCtrTestCases() {
        return Stream.of(
                arguments(
                        VtrList.of(
                                VectorOfTrust.of(CredentialTrustLevel.LOW_LEVEL),
                                VectorOfTrust.of(CredentialTrustLevel.MEDIUM_LEVEL)),
                        CredentialTrustLevel.LOW_LEVEL),
                arguments(
                        VtrList.of(
                                VectorOfTrust.of(CredentialTrustLevel.LOW_LEVEL),
                                VectorOfTrust.of(CredentialTrustLevel.LOW_LEVEL)),
                        CredentialTrustLevel.LOW_LEVEL),
                arguments(
                        VtrList.of(
                                VectorOfTrust.of(CredentialTrustLevel.MEDIUM_LEVEL),
                                VectorOfTrust.of(CredentialTrustLevel.MEDIUM_LEVEL)),
                        CredentialTrustLevel.MEDIUM_LEVEL),
                arguments(
                        VtrList.of(
                                VectorOfTrust.of(CredentialTrustLevel.MEDIUM_LEVEL),
                                VectorOfTrust.of(CredentialTrustLevel.LOW_LEVEL),
                                VectorOfTrust.of(CredentialTrustLevel.MEDIUM_LEVEL),
                                VectorOfTrust.of(CredentialTrustLevel.MEDIUM_LEVEL)),
                        CredentialTrustLevel.LOW_LEVEL),
                arguments(
                        VtrList.of(
                                VectorOfTrust.of(CredentialTrustLevel.MEDIUM_LEVEL),
                                VectorOfTrust.of(CredentialTrustLevel.LOW_LEVEL),
                                VectorOfTrust.of(CredentialTrustLevel.LOW_LEVEL),
                                VectorOfTrust.of(CredentialTrustLevel.LOW_LEVEL)),
                        CredentialTrustLevel.LOW_LEVEL));
    }

    private static Stream<Arguments> locsCssTestCases() {
        return Stream.of(
                arguments(
                        VtrList.of(
                                VectorOfTrust.of(
                                        CredentialTrustLevel.MEDIUM_LEVEL,
                                        LevelOfConfidence.HIGH_LEVEL)),
                        "P3"),
                arguments(
                        VtrList.of(
                                VectorOfTrust.of(
                                        CredentialTrustLevel.MEDIUM_LEVEL,
                                        LevelOfConfidence.MEDIUM_LEVEL),
                                VectorOfTrust.of(
                                        CredentialTrustLevel.MEDIUM_LEVEL,
                                        LevelOfConfidence.MEDIUM_LEVEL)),
                        "P2"),
                arguments(
                        VtrList.of(
                                VectorOfTrust.of(
                                        CredentialTrustLevel.MEDIUM_LEVEL,
                                        LevelOfConfidence.VERY_HIGH_LEVEL),
                                VectorOfTrust.of(
                                        CredentialTrustLevel.MEDIUM_LEVEL,
                                        LevelOfConfidence.LOW_LEVEL),
                                VectorOfTrust.of(
                                        CredentialTrustLevel.MEDIUM_LEVEL,
                                        LevelOfConfidence.MEDIUM_LEVEL),
                                VectorOfTrust.of(
                                        CredentialTrustLevel.MEDIUM_LEVEL,
                                        LevelOfConfidence.LOW_LEVEL),
                                VectorOfTrust.of(
                                        CredentialTrustLevel.MEDIUM_LEVEL,
                                        LevelOfConfidence.HMRC200)),
                        "P1,PCL200"));
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

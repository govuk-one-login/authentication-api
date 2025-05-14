package uk.gov.di.authentication.app.services;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.JWTAuthenticationClaimsSet;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.JWTID;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;
import uk.gov.di.orchestration.shared.api.DocAppCriAPI;
import uk.gov.di.orchestration.shared.exceptions.UnsuccessfulCredentialResponseException;
import uk.gov.di.orchestration.shared.helpers.NowHelper;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.KmsConnectionService;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

import static java.lang.String.format;
import static java.util.Collections.singletonList;
import static uk.gov.di.orchestration.shared.entity.IdentityClaims.CREDENTIAL_JWT;
import static uk.gov.di.orchestration.shared.helpers.HashHelper.hashSha256String;

public class DocAppCriService {

    private final ConfigurationService configurationService;
    private final KmsConnectionService kmsService;
    private final DocAppCriAPI docAppCriApi;
    private static final JWSAlgorithm TOKEN_ALGORITHM = JWSAlgorithm.ES256;
    private static final Long PRIVATE_KEY_JWT_EXPIRY = 5L;
    private static final Logger LOG = LogManager.getLogger(DocAppCriService.class);

    public DocAppCriService(
            ConfigurationService configurationService,
            KmsConnectionService kmsService,
            DocAppCriAPI docAppCriApi) {
        this.configurationService = configurationService;
        this.kmsService = kmsService;
        this.docAppCriApi = docAppCriApi;
    }

    public TokenRequest constructTokenRequest(String authCode) {
        LOG.info("Constructing token request");
        var codeGrant =
                new AuthorizationCodeGrant(
                        new AuthorizationCode(authCode),
                        configurationService.getDocAppAuthorisationCallbackURI());
        var tokenURI = docAppCriApi.tokenURI();
        var audience =
                configurationService.isDocAppNewAudClaimEnabled()
                        ? configurationService.getDocAppAudClaim()
                        : new Audience(tokenURI);
        var claimsSet =
                new JWTAuthenticationClaimsSet(
                        new ClientID(configurationService.getDocAppAuthorisationClientId()),
                        singletonList(audience),
                        NowHelper.nowPlus(PRIVATE_KEY_JWT_EXPIRY, ChronoUnit.MINUTES),
                        NowHelper.now(),
                        NowHelper.now(),
                        new JWTID());
        return new TokenRequest(
                tokenURI,
                generatePrivateKeyJwt(claimsSet),
                codeGrant,
                null,
                null,
                singletonList(tokenURI),
                null,
                Map.of(
                        "client_id",
                        singletonList(configurationService.getDocAppAuthorisationClientId())));
    }

    public TokenResponse sendTokenRequest(TokenRequest tokenRequest) {
        try {
            LOG.info("Sending TokenRequest");
            int count = 0;
            int maxTries = 2;
            TokenResponse tokenResponse;
            do {
                if (count > 0) LOG.warn("Retrying DocApp token request");
                count++;
                tokenResponse = TokenResponse.parse(tokenRequest.toHTTPRequest().send());
                if (!tokenResponse.indicatesSuccess()) {
                    HTTPResponse response = tokenResponse.toHTTPResponse();
                    LOG.warn(
                            format(
                                    "Unsuccessful %s response from DocApp token endpoint on attempt %d: %s ",
                                    response.getStatusCode(), count, response.getBody()));
                }
            } while (!tokenResponse.indicatesSuccess() && count < maxTries);
            return tokenResponse;
        } catch (IOException e) {
            LOG.error("Error whilst sending TokenRequest", e);
            throw new RuntimeException(e);
        } catch (ParseException e) {
            LOG.error("Error whilst parsing TokenResponse", e);
            throw new RuntimeException(e);
        }
    }

    public List<String> sendCriDataRequest(HTTPRequest request, String docAppSubjectId)
            throws UnsuccessfulCredentialResponseException {
        try {
            LOG.info("Sending userinfo request");
            int count = 0;
            int maxTries = 2;
            HTTPResponse response;
            do {
                if (count > 0) LOG.warn("Retrying DocApp cri data request");
                count++;
                response = request.send();
                if (!response.indicatesSuccess()) {
                    LOG.warn(
                            format(
                                    "Unsuccessful %s response from DocApp userinfo endpoint on attempt %d: %s ",
                                    response.getStatusCode(), count, response.getBody()));
                }
            } while (!response.indicatesSuccess() && count < maxTries);

            if (!response.indicatesSuccess()) {
                throw new UnsuccessfulCredentialResponseException(
                        format(
                                "Error %s when attempting to call CRI data endpoint: %s",
                                response.getStatusCode(), response.getBody()),
                        response.getStatusCode());
            }

            if (!response.getBodyAsJSONObject().get("sub").equals(docAppSubjectId)
                    && !configurationService.getEnvironment().equals("dev")
                    && !configurationService.getEnvironment().equals("build")) {
                throw new UnsuccessfulCredentialResponseException(
                        "Sub in CRI response does not match docAppSubjectId in client session");
            }

            List<SignedJWT> signedJWTS = parseResponse(response);
            LOG.info("Received successful userinfo response");
            return signedJWTS.stream().map(JWSObject::serialize).collect(Collectors.toList());
        } catch (IOException e) {
            throw new UnsuccessfulCredentialResponseException(
                    "Error when attempting to call CRI data endpoint", e);
        } catch (ParseException e) {
            throw new UnsuccessfulCredentialResponseException("Error parsing HTTP response", e);
        }
    }

    private List<SignedJWT> parseResponse(HTTPResponse response)
            throws UnsuccessfulCredentialResponseException {
        try {
            var contentAsJSONObject = response.getBodyAsJSONObject();
            if (Objects.isNull(contentAsJSONObject.get(CREDENTIAL_JWT.getValue()))) {
                throw new UnsuccessfulCredentialResponseException(
                        "No Credential JWT claim present");
            }
            var serializedSignedJWTs =
                    (List<String>) contentAsJSONObject.get(CREDENTIAL_JWT.getValue());
            List<SignedJWT> signedJWTs = new ArrayList<>();
            for (String jwt : serializedSignedJWTs) {
                signedJWTs.add(SignedJWT.parse(jwt));
            }
            return signedJWTs;
        } catch (ParseException e) {
            throw new UnsuccessfulCredentialResponseException("Error parsing CRI response", e);
        } catch (java.text.ParseException e) {
            throw new UnsuccessfulCredentialResponseException("Error parsing JWT", e);
        }
    }

    private PrivateKeyJWT generatePrivateKeyJwt(JWTAuthenticationClaimsSet claimsSet) {
        try {
            LOG.info("Generating PrivateKeyJWT");
            var docAppTokenSigningKeyAlias = configurationService.getDocAppTokenSigningKeyAlias();
            var signingKeyId =
                    kmsService
                            .getPublicKey(
                                    GetPublicKeyRequest.builder()
                                            .keyId(docAppTokenSigningKeyAlias)
                                            .build())
                            .keyId();
            var jwsHeader =
                    new JWSHeader.Builder(TOKEN_ALGORITHM)
                            .keyID(hashSha256String(signingKeyId))
                            .build();
            var encodedHeader = jwsHeader.toBase64URL();
            var encodedClaims = Base64URL.encode(claimsSet.toJWTClaimsSet().toString());
            var message = encodedHeader + "." + encodedClaims;
            var messageToSign = ByteBuffer.wrap(message.getBytes(StandardCharsets.UTF_8));
            var signRequest =
                    SignRequest.builder()
                            .message(SdkBytes.fromByteBuffer(messageToSign))
                            .keyId(docAppTokenSigningKeyAlias)
                            .signingAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256)
                            .build();
            var signResponse = kmsService.sign(signRequest);
            LOG.info("PrivateKeyJWT has been signed successfully");
            var signature =
                    Base64URL.encode(
                                    ECDSA.transcodeSignatureToConcat(
                                            signResponse.signature().asByteArray(),
                                            ECDSA.getSignatureByteArrayLength(TOKEN_ALGORITHM)))
                            .toString();
            return new PrivateKeyJWT(SignedJWT.parse(message + "." + signature));
        } catch (JOSEException | java.text.ParseException e) {
            LOG.error("Exception thrown when trying to parse SignedJWT or JWTClaimSet", e);
            throw new RuntimeException(e);
        }
    }
}

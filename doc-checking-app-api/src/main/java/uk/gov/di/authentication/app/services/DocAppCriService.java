package uk.gov.di.authentication.app.services;

import com.amazonaws.services.kms.model.GetPublicKeyRequest;
import com.amazonaws.services.kms.model.SignRequest;
import com.amazonaws.services.kms.model.SignResult;
import com.amazonaws.services.kms.model.SigningAlgorithmSpec;
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
import uk.gov.di.authentication.app.exception.UnsuccesfulCredentialResponseException;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

import static java.util.Collections.singletonList;
import static uk.gov.di.authentication.shared.entity.IdentityClaims.CREDENTIAL_JWT;
import static uk.gov.di.authentication.shared.helpers.ConstructUriHelper.buildURI;
import static uk.gov.di.authentication.shared.helpers.HashHelper.hashSha256String;

public class DocAppCriService {

    private final ConfigurationService configurationService;
    private final KmsConnectionService kmsService;
    private static final JWSAlgorithm TOKEN_ALGORITHM = JWSAlgorithm.ES256;
    private static final Long PRIVATE_KEY_JWT_EXPIRY = 5L;
    private static final Logger LOG = LogManager.getLogger(DocAppCriService.class);

    public DocAppCriService(
            ConfigurationService configurationService, KmsConnectionService kmsService) {
        this.configurationService = configurationService;
        this.kmsService = kmsService;
    }

    public TokenRequest constructTokenRequest(String authCode) {
        LOG.info("Constructing token request");
        var codeGrant =
                new AuthorizationCodeGrant(
                        new AuthorizationCode(authCode),
                        configurationService.getDocAppAuthorisationCallbackURI());
        var backendURI = configurationService.getDocAppBackendURI();
        var tokenURI = buildURI(backendURI.toString(), "token");
        var claimsSet =
                new JWTAuthenticationClaimsSet(
                        new ClientID(configurationService.getDocAppAuthorisationClientId()),
                        singletonList(new Audience(tokenURI)),
                        NowHelper.nowPlus(PRIVATE_KEY_JWT_EXPIRY, ChronoUnit.MINUTES),
                        NowHelper.now(),
                        NowHelper.now(),
                        new JWTID());
        return new TokenRequest(
                tokenURI,
                generatePrivateKeyJwt(claimsSet),
                codeGrant,
                null,
                singletonList(tokenURI),
                Map.of(
                        "client_id",
                        singletonList(configurationService.getDocAppAuthorisationClientId())));
    }

    public TokenResponse sendTokenRequest(TokenRequest tokenRequest) {
        try {
            LOG.info("Sending TokenRequest");
            return TokenResponse.parse(tokenRequest.toHTTPRequest().send());
        } catch (IOException e) {
            LOG.error("Error whilst sending TokenRequest", e);
            throw new RuntimeException(e);
        } catch (ParseException e) {
            LOG.error("Error whilst parsing TokenResponse", e);
            throw new RuntimeException(e);
        }
    }

    public List<String> sendCriDataRequest(HTTPRequest request, String docAppSubjectId) {
        try {
            LOG.info("Sending userinfo request");
            var response = request.send();
            if (!response.indicatesSuccess()) {
                LOG.error(
                        "Error {} when attempting to call CRI data endpoint: {}",
                        response.getStatusCode(),
                        response.getContent());
                throw new UnsuccesfulCredentialResponseException(
                        "Error response received from CRI");
            }

            if (!response.getContentAsJSONObject().get("sub").equals(docAppSubjectId)
                    && !configurationService.getEnvironment().equals("build")) {
                LOG.error("Sub in CRI response does not match docAppSubjectId in client session");
                throw new UnsuccesfulCredentialResponseException(
                        "Sub in CRI response does not match docAppSubjectId in client session");
            }

            List<SignedJWT> signedJWTS = parseResponse(response);
            LOG.info("Received successful userinfo response");
            return signedJWTS.stream().map(JWSObject::serialize).collect(Collectors.toList());
        } catch (IOException e) {
            LOG.error("Error when attempting to call CRI data endpoint", e);
            throw new UnsuccesfulCredentialResponseException(
                    "Error when attempting to call CRI data endpoint", e);
        } catch (ParseException e) {
            LOG.error("Error parsing HTTP response", e);
            throw new UnsuccesfulCredentialResponseException("Error parsing HTTP response", e);
        }
    }

    private List<SignedJWT> parseResponse(HTTPResponse response) {
        try {
            var contentAsJSONObject = response.getContentAsJSONObject();
            if (Objects.isNull(contentAsJSONObject.get(CREDENTIAL_JWT.getValue()))) {
                throw new UnsuccesfulCredentialResponseException("No Credential JWT claim present");
            }
            var serializedSignedJWTs =
                    (List<String>) contentAsJSONObject.get(CREDENTIAL_JWT.getValue());
            List<SignedJWT> signedJWTs = new ArrayList<>();
            for (String jwt : serializedSignedJWTs) {
                signedJWTs.add(SignedJWT.parse(jwt));
            }
            return signedJWTs;
        } catch (ParseException e) {
            throw new UnsuccesfulCredentialResponseException("Error parsing CRI response", e);
        } catch (java.text.ParseException e) {
            throw new UnsuccesfulCredentialResponseException("Error parsing JWT", e);
        }
    }

    private PrivateKeyJWT generatePrivateKeyJwt(JWTAuthenticationClaimsSet claimsSet) {
        try {
            LOG.info("Generating PrivateKeyJWT");
            var docAppTokenSigningKeyAlias = configurationService.getDocAppTokenSigningKeyAlias();
            var signingKeyId =
                    kmsService
                            .getPublicKey(
                                    new GetPublicKeyRequest().withKeyId(docAppTokenSigningKeyAlias))
                            .getKeyId();
            var jwsHeader =
                    new JWSHeader.Builder(TOKEN_ALGORITHM)
                            .keyID(hashSha256String(signingKeyId))
                            .build();
            var encodedHeader = jwsHeader.toBase64URL();
            var encodedClaims = Base64URL.encode(claimsSet.toJWTClaimsSet().toString());
            var message = encodedHeader + "." + encodedClaims;
            var messageToSign = ByteBuffer.wrap(message.getBytes());
            var signRequest = new SignRequest();
            signRequest.setMessage(messageToSign);
            signRequest.setKeyId(docAppTokenSigningKeyAlias);
            signRequest.setSigningAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256.toString());
            SignResult signResult = kmsService.sign(signRequest);
            LOG.info("PrivateKeyJWT has been signed successfully");
            var signature =
                    Base64URL.encode(
                                    ECDSA.transcodeSignatureToConcat(
                                            signResult.getSignature().array(),
                                            ECDSA.getSignatureByteArrayLength(TOKEN_ALGORITHM)))
                            .toString();
            return new PrivateKeyJWT(SignedJWT.parse(message + "." + signature));
        } catch (JOSEException | java.text.ParseException e) {
            LOG.error("Exception thrown when trying to parse SignedJWT or JWTClaimSet", e);
            throw new RuntimeException(e);
        }
    }
}

package uk.gov.di.orchestration.shared.services;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.oauth2.sdk.auth.verifier.ClientAuthenticationVerifier;
import com.nimbusds.oauth2.sdk.auth.verifier.InvalidClientException;
import com.nimbusds.oauth2.sdk.id.Audience;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.shared.api.OidcAPI;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.exceptions.ClientSignatureValidationException;
import uk.gov.di.orchestration.shared.validation.PrivateKeyJwtAuthPublicKeySelector;

import java.net.URI;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Collections;

import static uk.gov.di.orchestration.shared.helpers.ConstructUriHelper.buildURI;

public class ClientSignatureValidationService {

    private static final Logger LOG = LogManager.getLogger(ClientSignatureValidationService.class);

    private static final String TOKEN_PATH = "token";

    private final OidcAPI oidcAPI;

    public ClientSignatureValidationService(OidcAPI oidcApi) {
        this.oidcAPI = oidcApi;
    }

    public void validate(SignedJWT signedJWT, ClientRegistry client)
            throws ClientSignatureValidationException {
        try {
            var publicKey = getPublicKey(client);
            JWSVerifier verifier = new RSASSAVerifier((RSAPublicKey) publicKey);
            if (!signedJWT.verify(verifier)) {
                throw new ClientSignatureValidationException("Failed to verify Signed JWT.");
            }
        } catch (ClientSignatureValidationException
                | NoSuchAlgorithmException
                | InvalidKeySpecException
                | JOSEException e) {
            LOG.error("Error validating Signed JWT for Client: {}", client.getClientID());
            throw e instanceof ClientSignatureValidationException clientSigValException
                    ? clientSigValException
                    : new ClientSignatureValidationException(e);
        }
    }

    public void validateTokenClientAssertion(PrivateKeyJWT privateKeyJWT, ClientRegistry client)
            throws ClientSignatureValidationException {
        try {
            var publicKey = getPublicKey(client);
            ClientAuthenticationVerifier<?> authenticationVerifier =
                    new ClientAuthenticationVerifier<>(
                            new PrivateKeyJwtAuthPublicKeySelector(publicKey),
                            Collections.singleton(new Audience(getTokenURI().toString())));
            authenticationVerifier.verify(privateKeyJWT, null, null);
        } catch (InvalidClientException
                | NoSuchAlgorithmException
                | InvalidKeySpecException
                | JOSEException e) {
            LOG.error(
                    "Error validating Token Client Assertion JWT for Client: {}",
                    client.getClientID());
            throw new ClientSignatureValidationException(e);
        }
    }

    private PublicKey getPublicKey(ClientRegistry client)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] decodedKey = Base64.getMimeDecoder().decode(client.getPublicKey());
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodedKey);
        KeyFactory kf = KeyFactory.getInstance(KeyType.RSA.getValue());
        return kf.generatePublic(keySpec);
    }

    private URI getTokenURI() {
        return buildURI(oidcAPI.baseURI(), TOKEN_PATH);
    }
}

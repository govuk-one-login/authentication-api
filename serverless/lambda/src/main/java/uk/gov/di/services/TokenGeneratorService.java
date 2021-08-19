package uk.gov.di.services;

import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.amazonaws.services.kms.model.GetPublicKeyRequest;
import com.amazonaws.services.kms.model.GetPublicKeyResult;
import com.amazonaws.services.kms.model.MessageType;
import com.amazonaws.services.kms.model.SignRequest;
import com.amazonaws.services.kms.model.SignResult;
import com.amazonaws.services.kms.model.SigningAlgorithmSpec;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.nio.ByteBuffer;
import java.security.Provider;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.text.ParseException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.List;
import java.util.UUID;

public class TokenGeneratorService {

    private final AWSKMS kmsClient;
    private final String keyId;
    private static final Logger LOGGER = LoggerFactory.getLogger(TokenGeneratorService.class);

    public TokenGeneratorService(ConfigurationService configurationService) {
        if (configurationService.getLocalstackEndpointUri().isPresent()) {
            LOGGER.info(
                    "Localstack endpoint URI is present: "
                            + configurationService.getLocalstackEndpointUri().get());
            this.kmsClient =
                    AWSKMSClientBuilder.standard()
                            .withEndpointConfiguration(
                                    new AwsClientBuilder.EndpointConfiguration(
                                            configurationService.getLocalstackEndpointUri().get(),
                                            configurationService.getAwsRegion()))
                            .build();
        } else {
            this.kmsClient =
                    AWSKMSClientBuilder.standard()
                            .withRegion(configurationService.getAwsRegion())
                            .build();
        }
        this.keyId = configurationService.getTokenSigningKeyId();
    }

    public SignedJWT generateSignedIdToken(String clientId, Subject subject, String issuerUrl) {
        LocalDateTime localDateTime = LocalDateTime.now().plusMinutes(2);
        Date expiryDate = Date.from(localDateTime.atZone(ZoneId.systemDefault()).toInstant());
        IDTokenClaimsSet idTokenClaims =
                new IDTokenClaimsSet(
                        new Issuer(issuerUrl),
                        subject,
                        List.of(new Audience(clientId)),
                        expiryDate,
                        new Date());
        JWSHeader jwsHeader = generateJWSHeader();

        try {
            Base64URL encodedHeader = jwsHeader.toBase64URL();
            Base64URL encodedClaims = Base64URL.encode(idTokenClaims.toJWTClaimsSet().toString());
            String message = encodedHeader + "." + encodedClaims;
            ByteBuffer messageToSign = ByteBuffer.wrap(message.getBytes());
            SignResult signResult = sign(messageToSign);
            LOGGER.info("ID token has been signed successfully");
            String signature =
                    Base64URL.encode(
                                    ECDSA.transcodeSignatureToConcat(
                                            signResult.getSignature().array(),
                                            ECDSA.getSignatureByteArrayLength(JWSAlgorithm.ES256)))
                            .toString();
            return SignedJWT.parse(message + "." + signature);
        } catch (ParseException | com.nimbusds.oauth2.sdk.ParseException | JOSEException e) {
            LOGGER.error("Exception thrown when trying to parse SignedJWT or JWTClaimSet", e);
            throw new RuntimeException(e);
        }
    }

    public SignedJWT generateSignedAccessToken(
            String clientId, String issuerUrl, List<String> scopes) {
        LocalDateTime localDateTime = LocalDateTime.now().plusMinutes(2);
        Date expiryDate = Date.from(localDateTime.atZone(ZoneId.systemDefault()).toInstant());

        JWTClaimsSet claimsSet =
                new JWTClaimsSet.Builder()
                        .claim("scope", scopes)
                        .issuer(issuerUrl)
                        .expirationTime(expiryDate)
                        .issueTime(
                                Date.from(
                                        LocalDateTime.now()
                                                .atZone(ZoneId.systemDefault())
                                                .toInstant()))
                        .claim("client_id", clientId)
                        .jwtID(UUID.randomUUID().toString())
                        .build();
        JWSHeader jwsHeader = generateJWSHeader();
        try {
            Base64URL encodedHeader = jwsHeader.toBase64URL();
            Base64URL encodedClaims = Base64URL.encode(claimsSet.toString());
            String message = encodedHeader + "." + encodedClaims;
            ByteBuffer messageToSign = ByteBuffer.wrap(message.getBytes());
            SignResult signResult = sign(messageToSign);
            LOGGER.info("Access token has been signed successfully");
            String signature =
                    Base64URL.encode(
                                    ECDSA.transcodeSignatureToConcat(
                                            signResult.getSignature().array(),
                                            ECDSA.getSignatureByteArrayLength(JWSAlgorithm.ES256)))
                            .toString();
            return SignedJWT.parse(message + "." + signature);
        } catch (ParseException | JOSEException e) {
            LOGGER.error("Exception thrown when trying to parse SignedJWT or JWTClaimSet", e);
            throw new RuntimeException(e);
        }
    }

    public JWK getPublicKey() {
        LOGGER.info("Retrieving PublicKey from KMS");
        Provider bcProvider = new BouncyCastleProvider();
        GetPublicKeyRequest getPublicKeyRequest = new GetPublicKeyRequest();
        getPublicKeyRequest.setKeyId(keyId);
        GetPublicKeyResult publicKeyResult = kmsClient.getPublicKey(getPublicKeyRequest);
        try {
            SubjectPublicKeyInfo subjectKeyInfo =
                    SubjectPublicKeyInfo.getInstance(publicKeyResult.getPublicKey().array());
            PublicKey publicKey =
                    new JcaPEMKeyConverter().setProvider(bcProvider).getPublicKey(subjectKeyInfo);
            ECKey jwk =
                    new ECKey.Builder(Curve.P_256, (ECPublicKey) publicKey)
                            .keyID(keyId)
                            .keyUse(KeyUse.SIGNATURE)
                            .algorithm(new Algorithm(JWSAlgorithm.ES256.getName()))
                            .build();
            return JWK.parse(jwk.toJSONObject());
        } catch (PEMException e) {
            LOGGER.error("Error getting the PublicKey using the JcaPEMKeyConverter", e);
            throw new RuntimeException();
        } catch (ParseException e) {
            LOGGER.error("Error parsing the ECKey to JWK", e);
            throw new RuntimeException(e);
        }
    }

    private SignResult sign(ByteBuffer message) {
        SignRequest signRequest = new SignRequest();
        signRequest.setSigningAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256.toString());
        signRequest.setKeyId(keyId);
        signRequest.setMessage(message);
        signRequest.setMessageType(MessageType.RAW.toString());
        try {
            LOGGER.info("Signing message with KMS");
            return kmsClient.sign(signRequest);
        } catch (Exception e) {
            LOGGER.error("Exception thrown when attempting to sign with KMS", e);
            throw new RuntimeException(e);
        }
    }

    private JWSHeader generateJWSHeader() {
        return new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(keyId).build();
    }
}

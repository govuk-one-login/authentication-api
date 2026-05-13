package uk.gov.di.authentication.shared.services;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SignResponse;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;
import uk.gov.di.authentication.shared.helpers.NowHelper;

import java.nio.charset.StandardCharsets;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static uk.gov.di.authentication.shared.helpers.HashHelper.hashSha256String;

public class TokenService {

    private final ConfigurationService configService;
    private final KmsConnectionService kmsConnectionService;
    private static final Logger LOG = LogManager.getLogger(TokenService.class);

    public TokenService(
            ConfigurationService configService, KmsConnectionService kmsConnectionService) {
        this.configService = configService;
        this.kmsConnectionService = kmsConnectionService;
    }

    public AccessToken generateStorageTokenForMfaReset(Subject internalPairwiseSubject) {

        LOG.info("Generating storage token");
        Date expiryDate = NowHelper.nowPlus(configService.getSessionExpiry(), ChronoUnit.SECONDS);
        var jwtID = UUID.randomUUID().toString();

        LOG.info("Storage token being created with JWTID: {}", jwtID);

        List<String> aud = List.of(configService.getEVCSAudience(), configService.getIPVAudience());

        JWTClaimsSet.Builder claimSetBuilder =
                new JWTClaimsSet.Builder()
                        .claim("scope", "reverification")
                        .issuer(configService.getAuthIssuerClaimForEVCS())
                        .audience(aud)
                        .expirationTime(expiryDate)
                        .issueTime(NowHelper.now())
                        .subject(internalPairwiseSubject.getValue())
                        .jwtID(jwtID);

        SignedJWT signedJWT =
                generateSignedJwtUsingStorageKey(claimSetBuilder.build(), Optional.empty());

        return new BearerAccessToken(
                signedJWT.serialize(), configService.getAccessTokenExpiry(), null);
    }

    private SignedJWT generateSignedJwtUsingStorageKey(
            JWTClaimsSet claimsSet, Optional<String> type) {
        return generateSignedJWT(
                claimsSet,
                type,
                JWSAlgorithm.ES256,
                configService.getMfaResetStorageTokenSigningKeyAlias());
    }

    private SignedJWT generateSignedJWT(
            JWTClaimsSet claimsSet,
            Optional<String> type,
            JWSAlgorithm algorithm,
            String signingKey) {

        var signingKeyId =
                kmsConnectionService
                        .getPublicKey(GetPublicKeyRequest.builder().keyId(signingKey).build())
                        .keyId();

        try {
            var jwsHeader = new JWSHeader.Builder(algorithm).keyID(hashSha256String(signingKeyId));

            type.map(JOSEObjectType::new).ifPresent(jwsHeader::type);

            var signingAlgorithm =
                    algorithm == JWSAlgorithm.ES256
                            ? SigningAlgorithmSpec.ECDSA_SHA_256
                            : SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_256;

            Base64URL encodedHeader = jwsHeader.build().toBase64URL();
            Base64URL encodedClaims = Base64URL.encode(claimsSet.toString());
            String message = encodedHeader + "." + encodedClaims;
            SignRequest signRequest =
                    SignRequest.builder()
                            .message(
                                    SdkBytes.fromByteArray(
                                            message.getBytes(StandardCharsets.UTF_8)))
                            .keyId(signingKey)
                            .signingAlgorithm(signingAlgorithm)
                            .build();
            SignResponse signResult = kmsConnectionService.sign(signRequest);
            LOG.info("Token has been signed successfully using {}", algorithm.getName());

            if (algorithm == JWSAlgorithm.RS256) {
                return SignedJWT.parse(
                        message + "." + Base64URL.encode(signResult.signature().asByteArray()));
            }

            String signature =
                    Base64URL.encode(
                                    ECDSA.transcodeSignatureToConcat(
                                            signResult.signature().asByteArray(),
                                            ECDSA.getSignatureByteArrayLength(algorithm)))
                            .toString();
            return SignedJWT.parse(message + "." + signature);
        } catch (java.text.ParseException | JOSEException e) {
            LOG.error("Exception thrown when trying to parse SignedJWT or JWTClaimSet", e);
            throw new RuntimeException(e);
        }
    }
}

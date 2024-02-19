package uk.gov.di.authentication.ipv.services;

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
import uk.gov.di.orchestration.shared.helpers.NowHelper;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.KmsConnectionService;

import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static uk.gov.di.orchestration.shared.helpers.HashHelper.hashSha256String;

public class StorageTokenService {

    private static final Logger LOG = LogManager.getLogger(IPVAuthorisationService.class);
    private final ConfigurationService configurationService;
    private final KmsConnectionService kmsConnectionService;

    public StorageTokenService(ConfigurationService configurationService) {
        this(configurationService, new KmsConnectionService(configurationService));
    }

    public StorageTokenService(
            ConfigurationService configurationService, KmsConnectionService kmsConnectionService) {
        this.configurationService = configurationService;
        this.kmsConnectionService = kmsConnectionService;
    }

    public AccessToken generateAndSignStorageToken(
            Subject internalPairwiseSubject, JWSAlgorithm signingAlgorithm) {

        LOG.info("Generating storage token");
        Date expiryDate =
                NowHelper.nowPlus(configurationService.getSessionExpiry(), ChronoUnit.SECONDS);
        var jwtID = UUID.randomUUID().toString();

        LOG.info("Storage token being created with JWTID: {}", jwtID);

        List<String> aud =
                List.of(
                        configurationService.getCredentialStoreURI().toString(),
                        configurationService.getIPVAudience());

        JWTClaimsSet.Builder claimSetBuilder =
                new JWTClaimsSet.Builder()
                        .issuer(configurationService.getOidcApiBaseURL().get())
                        .audience(aud)
                        .expirationTime(expiryDate)
                        .issueTime(NowHelper.now())
                        .subject(internalPairwiseSubject.getValue())
                        .jwtID(jwtID);

        SignedJWT signedJWT =
                generateSignedJWT(claimSetBuilder.build(), Optional.empty(), signingAlgorithm);

        return new BearerAccessToken(
                signedJWT.serialize(), configurationService.getAccessTokenExpiry(), null);
    }

    public SignedJWT generateSignedJWT(
            JWTClaimsSet claimsSet, Optional<String> type, JWSAlgorithm algorithm) {

        var signingKeyId = getSigningKeyId(algorithm);

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
                            .message(SdkBytes.fromByteArray(message.getBytes()))
                            .keyId(signingKeyId)
                            .signingAlgorithm(signingAlgorithm)
                            .build();
            SignResponse signResult = kmsConnectionService.sign(signRequest);
            LOG.info("Storage token has been signed successfully using {}", algorithm.getName());

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

    private String getSigningKeyId(JWSAlgorithm algorithm) {
        var signingKey =
                algorithm == JWSAlgorithm.ES256
                        ? configurationService.getTokenSigningKeyAlias()
                        : configurationService.getTokenSigningKeyRsaAlias();
        return kmsConnectionService
                .getPublicKey(GetPublicKeyRequest.builder().keyId(signingKey).build())
                .keyId();
    }
}

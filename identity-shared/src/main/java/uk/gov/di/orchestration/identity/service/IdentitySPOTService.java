package uk.gov.di.orchestration.identity.service;

import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.identity.entity.LogIds;
import uk.gov.di.orchestration.identity.entity.SPOTClaims;
import uk.gov.di.orchestration.identity.entity.SPOTRequest;
import uk.gov.di.orchestration.shared.api.OidcAPI;
import uk.gov.di.orchestration.shared.entity.AuthUserInfoClaims;
import uk.gov.di.orchestration.shared.entity.IdentityClaims;
import uk.gov.di.orchestration.shared.services.AwsSqsClient;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.SerializationService;

import static uk.gov.di.orchestration.shared.entity.IdentityClaims.VOT;

public class IdentitySPOTService {
    private static final Logger LOG = LogManager.getLogger(IdentitySPOTService.class);
    private final ConfigurationService configurationService;
    private final AwsSqsClient spotSqsClient;
    private final OidcAPI oidcApi;
    private final SerializationService objectMapper;

    public IdentitySPOTService(
            ConfigurationService configurationService,
            AwsSqsClient spotSqsClient,
            OidcAPI oidcApi,
            SerializationService objectMapper) {
        this.configurationService = configurationService;
        this.spotSqsClient = spotSqsClient;
        this.oidcApi = oidcApi;
        this.objectMapper = objectMapper;
    }

    public void queueSPOTRequest(
            LogIds logIds,
            String sectorIdentifier,
            UserInfo authUserInfo,
            Subject pairwiseSubject,
            UserInfo userIdentityUserInfo,
            String clientId) {
        LOG.info("Constructing SPOT request ready to queue");
        var spotClaimsBuilder =
                SPOTClaims.builder()
                        .withClaim(VOT.getValue(), userIdentityUserInfo.getClaim(VOT.getValue()))
                        .withClaim(
                                IdentityClaims.CREDENTIAL_JWT.getValue(),
                                userIdentityUserInfo
                                        .toJSONObject()
                                        .get(IdentityClaims.CREDENTIAL_JWT.getValue()))
                        .withClaim(
                                IdentityClaims.CORE_IDENTITY.getValue(),
                                userIdentityUserInfo
                                        .toJSONObject()
                                        .get(IdentityClaims.CORE_IDENTITY.getValue()))
                        .withVtm(oidcApi.trustmarkURI().toString());

        var spotRequest =
                new SPOTRequest(
                        spotClaimsBuilder.build(),
                        authUserInfo.getStringClaim(AuthUserInfoClaims.LOCAL_ACCOUNT_ID.getValue()),
                        authUserInfo.getStringClaim(AuthUserInfoClaims.SALT.getValue()),
                        sectorIdentifier,
                        pairwiseSubject.getValue(),
                        logIds,
                        clientId);
        var spotRequestString = objectMapper.writeValueAsString(spotRequest);
        if (configurationService.isNewSpotRequestQueueWritingEnabled()) {
            spotSqsClient.send(spotRequestString);
        }
        LOG.info("SPOT request placed on queue");
    }
}

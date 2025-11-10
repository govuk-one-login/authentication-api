package uk.gov.di.authentication.oidc.services;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import net.minidev.json.JSONArray;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.app.services.DynamoDocAppCriService;
import uk.gov.di.authentication.oidc.entity.AccessTokenInfo;
import uk.gov.di.authentication.oidc.exceptions.UserInfoException;
import uk.gov.di.orchestration.shared.entity.AuthUserInfoClaims;
import uk.gov.di.orchestration.shared.entity.CustomScopeValue;
import uk.gov.di.orchestration.shared.entity.ValidClaims;
import uk.gov.di.orchestration.shared.exceptions.AccessTokenException;
import uk.gov.di.orchestration.shared.exceptions.ClientNotFoundException;
import uk.gov.di.orchestration.shared.helpers.ClientSubjectHelper;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.services.AuthenticationUserInfoStorageService;
import uk.gov.di.orchestration.shared.services.CloudwatchMetricsService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.DynamoClientService;
import uk.gov.di.orchestration.shared.services.DynamoIdentityService;
import uk.gov.di.orchestration.shared.services.SerializationService;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;

public class UserInfoService {
    private final AuthenticationUserInfoStorageService userInfoStorageService;
    private final DynamoIdentityService identityService;
    private final DynamoClientService dynamoClientService;
    private final DynamoDocAppCriService dynamoDocAppCriService;
    private final CloudwatchMetricsService cloudwatchMetricsService;
    private final ConfigurationService configurationService;
    protected final Json objectMapper = SerializationService.getInstance();
    private static final Logger LOG = LogManager.getLogger(UserInfoService.class);

    public UserInfoService(
            DynamoIdentityService identityService,
            DynamoClientService dynamoClientService,
            DynamoDocAppCriService dynamoDocAppCriService,
            CloudwatchMetricsService cloudwatchMetricsService,
            ConfigurationService configurationService,
            AuthenticationUserInfoStorageService userInfoStorageService) {
        this.identityService = identityService;
        this.dynamoClientService = dynamoClientService;
        this.dynamoDocAppCriService = dynamoDocAppCriService;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
        this.configurationService = configurationService;
        this.userInfoStorageService = userInfoStorageService;
    }

    public String calculateSubjectForAudit(AccessTokenInfo accessTokenInfo) {
        LOG.info("Calculating Subject for audit payload");
        if (accessTokenInfo.scopes().contains(CustomScopeValue.DOC_CHECKING_APP.getValue())) {
            LOG.info("Getting subject for Doc App user");
            return accessTokenInfo.subject();
        } else {
            LOG.info("Calculating internal common subject identifier");
            return accessTokenInfo.internalPairwiseSubjectId();
        }
    }

    public UserInfo populateUserInfo(AccessTokenInfo accessTokenInfo)
            throws AccessTokenException, ClientNotFoundException {
        LOG.info("Populating UserInfo");
        UserInfo userInfo = new UserInfo(new Subject(accessTokenInfo.subject()));
        if (accessTokenInfo.scopes().contains(CustomScopeValue.DOC_CHECKING_APP.getValue())) {
            return populateDocAppUserInfo(accessTokenInfo, userInfo);
        }

        populateInfo(userInfo, accessTokenInfo);

        if (configurationService.isIdentityEnabled()
                && Objects.nonNull(accessTokenInfo.identityClaims())) {
            return populateIdentityInfo(accessTokenInfo, userInfo);
        } else {
            LOG.info("No identity claims present");
            return userInfo;
        }
    }

    private void populateInfo(UserInfo userInfo, AccessTokenInfo accessTokenInfo)
            throws AccessTokenException, ClientNotFoundException {
        UserInfo tmpUserInfo;
        try {
            Optional<UserInfo> userInfoFromStorage =
                    userInfoStorageService.getAuthenticationUserInfo(
                            accessTokenInfo.internalPairwiseSubjectId(),
                            accessTokenInfo.journeyId());

            if (userInfoFromStorage.isEmpty()) {
                throw new AccessTokenException(
                        "Unable to find user info for subject", BearerTokenError.INVALID_TOKEN);
            }

            tmpUserInfo = userInfoFromStorage.get();
        } catch (ParseException e) {
            throw new AccessTokenException(
                    "Error finding user info for subject", BearerTokenError.INVALID_TOKEN);
        }

        // TODO-922: temporary logs for checking all is working as expected
        LOG.info("is email attached to userinfo table: {}", tmpUserInfo.getEmailAddress() != null);
        //
        if (accessTokenInfo.scopes().contains(OIDCScopeValue.EMAIL.getValue())) {
            userInfo.setEmailAddress(tmpUserInfo.getEmailAddress());
            userInfo.setEmailVerified(tmpUserInfo.getEmailVerified());
        }
        if (accessTokenInfo.scopes().contains(OIDCScopeValue.PHONE.getValue())) {
            userInfo.setPhoneNumber(tmpUserInfo.getPhoneNumber());
            userInfo.setPhoneNumberVerified(tmpUserInfo.getPhoneNumberVerified());
        }
        if (accessTokenInfo.scopes().contains(CustomScopeValue.GOVUK_ACCOUNT.getValue())) {
            userInfo.setClaim(
                    AuthUserInfoClaims.LEGACY_SUBJECT_ID.getValue(),
                    tmpUserInfo.getClaim(AuthUserInfoClaims.LEGACY_SUBJECT_ID.getValue()));
        }
        if (accessTokenInfo.scopes().contains(CustomScopeValue.ACCOUNT_MANAGEMENT.getValue())) {
            userInfo.setClaim(
                    AuthUserInfoClaims.PUBLIC_SUBJECT_ID.getValue(),
                    tmpUserInfo.getClaim(AuthUserInfoClaims.PUBLIC_SUBJECT_ID.getValue()));
        }
        if (accessTokenInfo.scopes().contains(CustomScopeValue.WALLET_SUBJECT_ID.getValue())) {
            var walletSubjectID = calculateWalletSubjectID(accessTokenInfo);
            userInfo.setClaim("wallet_subject_id", walletSubjectID);
        }
    }

    private UserInfo populateIdentityInfo(AccessTokenInfo accessTokenInfo, UserInfo userInfo) {
        LOG.info("Populating IdentityInfo");
        var identityCredentials =
                identityService.getIdentityCredentials(accessTokenInfo.journeyId()).orElse(null);
        if (Objects.isNull(identityCredentials)) {
            LOG.info("No identity credentials present");
            return userInfo;
        }
        var coreIdentityClaimIsPresent =
                accessTokenInfo.identityClaims().stream()
                        .anyMatch(t -> t.equals(ValidClaims.CORE_IDENTITY_JWT.getValue()));
        if (Objects.nonNull(identityCredentials.getCoreIdentityJWT())
                && coreIdentityClaimIsPresent) {
            LOG.info("Setting coreIdentityJWT claim in userinfo response");
            userInfo.setClaim(
                    ValidClaims.CORE_IDENTITY_JWT.getValue(),
                    identityCredentials.getCoreIdentityJWT());
            incrementClaimIssuedCounter(
                    ValidClaims.CORE_IDENTITY_JWT.getValue(), accessTokenInfo.clientID());
        }
        if (Objects.nonNull(identityCredentials.getAdditionalClaims())) {
            identityCredentials.getAdditionalClaims().entrySet().stream()
                    .filter(t -> accessTokenInfo.identityClaims().contains(t.getKey()))
                    .forEach(
                            t -> {
                                try {
                                    userInfo.setClaim(
                                            t.getKey(),
                                            objectMapper.readValue(t.getValue(), JSONArray.class));
                                    incrementClaimIssuedCounter(
                                            t.getKey(), accessTokenInfo.clientID());
                                } catch (Json.JsonException e) {
                                    LOG.error("Unable to deserialize additional identity claims");
                                    throw new RuntimeException();
                                }
                            });
        }
        LOG.info("UserInfo populated with Identity claims");
        return userInfo;
    }

    private UserInfo populateDocAppUserInfo(AccessTokenInfo accessTokenInfo, UserInfo userInfo) {
        LOG.info("Populating DocAppUserInfo");
        return dynamoDocAppCriService
                .getDocAppCredential(accessTokenInfo.subject())
                .map(
                        docAppCredential -> {
                            userInfo.setClaim(
                                    "doc-app-credential", docAppCredential.getCredential());
                            incrementClaimIssuedCounter(
                                    "doc-app-credential", accessTokenInfo.clientID());
                            return userInfo;
                        })
                .orElseThrow(
                        () -> {
                            LOG.error("Unable to retrieve docAppCredential for Subject.");
                            throw new UserInfoException(
                                    "Unable to retrieve docAppCredential for Subject.");
                        });
    }

    private void incrementClaimIssuedCounter(String claimName, String clientID) {
        cloudwatchMetricsService.incrementCounter(
                "ClaimIssued",
                Map.of(
                        "Environment",
                        configurationService.getEnvironment(),
                        "Client",
                        clientID,
                        "Claim",
                        claimName));
    }

    private String calculateWalletSubjectID(AccessTokenInfo accessTokenInfo)
            throws ClientNotFoundException {
        var client =
                dynamoClientService
                        .getClient(accessTokenInfo.clientID())
                        .orElseThrow(() -> new ClientNotFoundException(accessTokenInfo.clientID()));
        var sectorID =
                ClientSubjectHelper.getSectorIdentifierForClient(
                        client, configurationService.getInternalSectorURI());
        var commonSubjectID = accessTokenInfo.internalPairwiseSubjectId();
        return ClientSubjectHelper.calculateWalletSubjectIdentifier(sectorID, commonSubjectID);
    }
}

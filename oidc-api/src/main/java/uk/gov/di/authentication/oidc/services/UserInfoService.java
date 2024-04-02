package uk.gov.di.authentication.oidc.services;

import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import net.minidev.json.JSONArray;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.app.services.DynamoDocAppService;
import uk.gov.di.authentication.oidc.entity.AccessTokenInfo;
import uk.gov.di.authentication.oidc.entity.AuthUserInfoClaims;
import uk.gov.di.authentication.oidc.exceptions.UserInfoException;
import uk.gov.di.orchestration.shared.entity.CustomScopeValue;
import uk.gov.di.orchestration.shared.entity.ValidClaims;
import uk.gov.di.orchestration.shared.exceptions.AccessTokenException;
import uk.gov.di.orchestration.shared.exceptions.ClientNotFoundException;
import uk.gov.di.orchestration.shared.helpers.ClientSubjectHelper;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.services.AuthenticationService;
import uk.gov.di.orchestration.shared.services.AuthenticationUserInfoStorageService;
import uk.gov.di.orchestration.shared.services.CloudwatchMetricsService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.DynamoClientService;
import uk.gov.di.orchestration.shared.services.DynamoIdentityService;
import uk.gov.di.orchestration.shared.services.SerializationService;

import java.util.Map;
import java.util.Objects;

public class UserInfoService {
    private final AuthenticationUserInfoStorageService userInfoStorageService;
    private final AuthenticationService authenticationService;
    private final DynamoIdentityService identityService;
    private final DynamoClientService dynamoClientService;
    private final DynamoDocAppService dynamoDocAppService;
    private final CloudwatchMetricsService cloudwatchMetricsService;
    private final ConfigurationService configurationService;
    protected final Json objectMapper = SerializationService.getInstance();
    private static final Logger LOG = LogManager.getLogger(UserInfoService.class);

    public UserInfoService(
            AuthenticationService authenticationService,
            DynamoIdentityService identityService,
            DynamoClientService dynamoClientService,
            DynamoDocAppService dynamoDocAppService,
            CloudwatchMetricsService cloudwatchMetricsService,
            ConfigurationService configurationService,
            AuthenticationUserInfoStorageService userInfoStorageService) {
        this.authenticationService = authenticationService;
        this.identityService = identityService;
        this.dynamoClientService = dynamoClientService;
        this.dynamoDocAppService = dynamoDocAppService;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
        this.configurationService = configurationService;
        this.userInfoStorageService = userInfoStorageService;
    }

    public String calculateSubjectForAudit(AccessTokenInfo accessTokenInfo) {
        LOG.info("Calculating Subject for audit payload");
        if (accessTokenInfo.getScopes().contains(CustomScopeValue.DOC_CHECKING_APP.getValue())) {
            LOG.info("Getting subject for Doc App user");
            return accessTokenInfo.getSubject();
        } else {
            LOG.info("Calculating internal common subject identifier");
            var userProfile =
                    authenticationService.getUserProfileFromSubject(
                            accessTokenInfo.getAccessTokenStore().getInternalSubjectId());
            return ClientSubjectHelper.getSubjectWithSectorIdentifier(
                            userProfile,
                            configurationService.getInternalSectorUri(),
                            authenticationService)
                    .getValue();
        }
    }

    public UserInfo populateUserInfo(AccessTokenInfo accessTokenInfo)
            throws AccessTokenException, ClientNotFoundException {
        LOG.info("Populating UserInfo");
        UserInfo userInfo = new UserInfo(new Subject(accessTokenInfo.getSubject()));
        if (accessTokenInfo.getScopes().contains(CustomScopeValue.DOC_CHECKING_APP.getValue())) {
            return populateDocAppUserInfo(accessTokenInfo, userInfo);
        }

        populateInfo(userInfo, accessTokenInfo);

        if (configurationService.isIdentityEnabled()
                && Objects.nonNull(accessTokenInfo.getIdentityClaims())) {
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
            var authUserInfo =
                    userInfoStorageService.getAuthenticationUserInfoData(
                            accessTokenInfo.getAccessTokenStore().getInternalPairwiseSubjectId());

            if (authUserInfo.isPresent()) {
                tmpUserInfo = new UserInfo(JSONObjectUtils.parse(authUserInfo.get().getUserInfo()));
            } else {
                throw new AccessTokenException(
                        "Unable to find subject", BearerTokenError.INVALID_TOKEN);
            }
        } catch (Exception e) {
            throw new AccessTokenException(
                    "Unable to get user info for Subject", BearerTokenError.INVALID_TOKEN);
        }

        if (accessTokenInfo.getScopes().contains(OIDCScopeValue.EMAIL.getValue())) {
            userInfo.setEmailAddress(tmpUserInfo.getEmailAddress());
            userInfo.setEmailVerified(tmpUserInfo.getEmailVerified());
        }
        if (accessTokenInfo.getScopes().contains(OIDCScopeValue.PHONE.getValue())) {
            userInfo.setPhoneNumber(tmpUserInfo.getPhoneNumber());
            userInfo.setPhoneNumberVerified(tmpUserInfo.getPhoneNumberVerified());
        }
        if (accessTokenInfo.getScopes().contains(CustomScopeValue.GOVUK_ACCOUNT.getValue())) {
            userInfo.setClaim(
                    AuthUserInfoClaims.LEGACY_SUBJECT_ID.getValue(),
                    tmpUserInfo.getClaim(AuthUserInfoClaims.LEGACY_SUBJECT_ID.getValue()));
        }
        if (accessTokenInfo.getScopes().contains(CustomScopeValue.ACCOUNT_MANAGEMENT.getValue())) {
            userInfo.setClaim(
                    AuthUserInfoClaims.PUBLIC_SUBJECT_ID.getValue(),
                    tmpUserInfo.getClaim(AuthUserInfoClaims.PUBLIC_SUBJECT_ID.getValue()));
        }
        if (accessTokenInfo.getScopes().contains(CustomScopeValue.WALLET_SUBJECT_ID.getValue())) {
            var walletSubjectID = calculateWalletSubjectID(accessTokenInfo);
            userInfo.setClaim("wallet_subject_id", walletSubjectID);
        }
    }

    private UserInfo populateIdentityInfo(AccessTokenInfo accessTokenInfo, UserInfo userInfo) {
        LOG.info("Populating IdentityInfo");
        var identityCredentials =
                identityService.getIdentityCredentials(accessTokenInfo.getSubject()).orElse(null);
        if (Objects.isNull(identityCredentials)) {
            LOG.info("No identity credentials present");
            return userInfo;
        }
        var coreIdentityClaimIsPresent =
                accessTokenInfo.getIdentityClaims().stream()
                        .anyMatch(t -> t.equals(ValidClaims.CORE_IDENTITY_JWT.getValue()));
        if (Objects.nonNull(identityCredentials.getCoreIdentityJWT())
                && coreIdentityClaimIsPresent) {
            LOG.info("Setting coreIdentityJWT claim in userinfo response");
            userInfo.setClaim(
                    ValidClaims.CORE_IDENTITY_JWT.getValue(),
                    identityCredentials.getCoreIdentityJWT());
            incrementClaimIssuedCounter(
                    ValidClaims.CORE_IDENTITY_JWT.getValue(), accessTokenInfo.getClientID());
        }
        if (Objects.nonNull(identityCredentials.getAdditionalClaims())) {
            identityCredentials.getAdditionalClaims().entrySet().stream()
                    .filter(t -> accessTokenInfo.getIdentityClaims().contains(t.getKey()))
                    .forEach(
                            t -> {
                                try {
                                    userInfo.setClaim(
                                            t.getKey(),
                                            objectMapper.readValue(t.getValue(), JSONArray.class));
                                    incrementClaimIssuedCounter(
                                            t.getKey(), accessTokenInfo.getClientID());
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
        return dynamoDocAppService
                .getDocAppCredential(accessTokenInfo.getSubject())
                .map(
                        docAppCredential -> {
                            userInfo.setClaim(
                                    "doc-app-credential", docAppCredential.getCredential());
                            incrementClaimIssuedCounter(
                                    "doc-app-credential", accessTokenInfo.getClientID());
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
                        .getClient(accessTokenInfo.getClientID())
                        .orElseThrow(
                                () -> new ClientNotFoundException(accessTokenInfo.getClientID()));
        var sectorID =
                ClientSubjectHelper.getSectorIdentifierForClient(
                        client, configurationService.getInternalSectorUri());
        var commonSubjectID = accessTokenInfo.getAccessTokenStore().getInternalPairwiseSubjectId();
        return ClientSubjectHelper.calculateWalletSubjectIdentifier(sectorID, commonSubjectID);
    }
}

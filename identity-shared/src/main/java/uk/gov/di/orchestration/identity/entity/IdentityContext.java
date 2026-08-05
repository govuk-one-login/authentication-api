package uk.gov.di.orchestration.identity.entity;

import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.OrchClientSessionItem;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem;

public record IdentityContext(
        OrchSessionItem orchSessionItem,
        OrchClientSessionItem orchClientSessionItem,
        ClientRegistry clientRegistry,
        UserInfo authUserInfo,
        AuthenticationRequest authRequest) {}

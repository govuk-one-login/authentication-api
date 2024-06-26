package uk.gov.di.authentication.oidc.entity;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.oauth2.sdk.ErrorObject;

public record JwksResponse(JWK jwk, ErrorObject error) {}

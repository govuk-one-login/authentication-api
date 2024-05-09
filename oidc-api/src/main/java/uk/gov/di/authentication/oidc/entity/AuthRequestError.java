package uk.gov.di.authentication.oidc.entity;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.id.State;

import java.net.URI;

public record AuthRequestError(ErrorObject errorObject, URI redirectURI, State state) {}

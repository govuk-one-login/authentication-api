package uk.gov.di.authentication.frontendapi.entity;

import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;

import java.util.Optional;

public record UserDetails(
        Optional<UserProfile> maybeUserProfile, Optional<UserCredentials> maybeUserCredentials) {}

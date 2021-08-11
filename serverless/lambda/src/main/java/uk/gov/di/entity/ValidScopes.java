package uk.gov.di.entity;

public enum ValidScopes {
    OPENID,
    PHONE,
    EMAIL;

    public String scopesLowerCase() {
        return name().toLowerCase();
    }
}

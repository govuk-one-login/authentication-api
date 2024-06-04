package uk.gov.di.orchestration.shared.entity;

import java.util.List;

public interface ClientConfigRequest {

    public String getClientName();

    public List<String> getRedirectUris();

    public List<String> getContacts();

    public String getPublicKey();

    public List<String> getScopes();

    public List<String> getPostLogoutRedirectUris();

    public String getServiceType();

    public List<String> getClaims();

    public String getSectorIdentifierUri();

    public String getClientType();

    public List<String> getClientLoCs();

    public String getBackChannelLogoutUri();

    public String getIdTokenSigningAlgorithm();
}

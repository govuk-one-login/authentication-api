package uk.gov.di.authentication.app.services;

import uk.gov.di.authentication.app.entity.DocAppCredential;
import uk.gov.di.orchestration.shared.services.BaseDynamoService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;

public class DynamoDocAppService extends BaseDynamoService<DocAppCredential> {

    private final long timeToExist;

    public DynamoDocAppService(ConfigurationService configurationService) {
        super(DocAppCredential.class, "doc-app-credential", configurationService);
        this.timeToExist = configurationService.getAccessTokenExpiry();
    }
}

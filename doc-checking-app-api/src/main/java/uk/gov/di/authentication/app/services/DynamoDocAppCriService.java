package uk.gov.di.authentication.app.services;

import uk.gov.di.authentication.app.entity.DocAppCredential;
import uk.gov.di.orchestration.shared.helpers.NowHelper;
import uk.gov.di.orchestration.shared.services.BaseDynamoService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;

import java.time.temporal.ChronoUnit;
import java.util.List;

public class DynamoDocAppCriService extends BaseDynamoService<DocAppCredential> {

    private final long timeToExist;

    public DynamoDocAppCriService(ConfigurationService configurationService) {
        super(DocAppCredential.class, "Orch-Doc-App-Credential", configurationService, true);
        this.timeToExist = configurationService.getAccessTokenExpiry();
    }

    public void addDocAppCredential(String subjectID, List<String> credential) {
        var docAppCredential =
                new DocAppCredential()
                        .withSubjectID(subjectID)
                        .withCredential(credential)
                        .withTimeToExist(
                                NowHelper.nowPlus(timeToExist, ChronoUnit.SECONDS)
                                        .toInstant()
                                        .getEpochSecond());

        put(docAppCredential);
    }
}

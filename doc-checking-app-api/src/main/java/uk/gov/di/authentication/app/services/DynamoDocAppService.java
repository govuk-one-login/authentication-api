package uk.gov.di.authentication.app.services;

import uk.gov.di.authentication.app.entity.DocAppCredential;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.services.BaseDynamoService;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;

public class DynamoDocAppService extends BaseDynamoService<DocAppCredential> {

    private final long timeToExist;

    public DynamoDocAppService(ConfigurationService configurationService) {
        super(DocAppCredential.class, "doc-app-credential", configurationService);
        this.timeToExist = configurationService.getAccessTokenExpiry();
    }

    public Optional<DocAppCredential> getDocAppCredential(String subjectID) {
        return get(subjectID)
                .filter(t -> t.getTimeToExist() > NowHelper.now().toInstant().getEpochSecond());
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

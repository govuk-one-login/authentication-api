package uk.gov.di.authentication.utils.helpers;

import uk.gov.di.authentication.utils.entity.InactiveAccountTrackerItem;

import java.util.ArrayList;
import java.util.List;

public class InactiveAccountDataExportBatchWriteService {

    private final List<InactiveAccountTrackerItem> buffer = new ArrayList<>();

    public InactiveAccountDataExportBatchWriteService() {}

    public void add(InactiveAccountTrackerItem item) {
        buffer.add(item);
    }
}

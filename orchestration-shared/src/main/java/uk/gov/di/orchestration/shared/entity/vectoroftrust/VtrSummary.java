package uk.gov.di.orchestration.shared.entity.vectoroftrust;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.JsonAdapter;
import org.jetbrains.annotations.NotNull;
import uk.gov.di.orchestration.shared.serialization.VtrListAdapter;

/**
 * A summary of a processed VTR Request.
 * @param fullRequest The original request.
 * @param chosenVector The chosen un-normalised VoT taken directly from the VTR Request.
 * @param effectiveVector The equivalent VoT normalised against the requestVersion.
 * @param requestVersion The VoT Vocabulary Version the fullRequest was validated against to normalise the
 *                       effectiveVector.
 */
public record VtrSummary(@NotNull
                         @Expose
                         @JsonAdapter(VtrListAdapter.class)
                         VtrRequest fullRequest,
                         @NotNull
                         @Expose
                         VectorOfTrust chosenVector,
                         @NotNull
                         @Expose
                         VectorOfTrust effectiveVector,
                         @NotNull
                         @Expose
                         VotVocabVersion requestVersion) {
}
package uk.gov.di.authentication.deliveryreceiptsapi.entity;

public class NotifyReference {
    private String uniqueNotificationReference = null;
    private String clientSessionId = null;

    // See AUT-4061
    // New-style references are formatted "{unique_notification_reference}/{client_session_id}"
    // whereas old-style references were "{client_session_id}" or null.
    public NotifyReference(String reference) {
        if (reference == null || reference.isEmpty()) {
            return;
        }

        if (reference.contains("/")) {
            var parts = reference.split("/");
            this.uniqueNotificationReference = parts[0];
            this.clientSessionId = parts[1];
        } else {
            this.clientSessionId = reference;
        }
    }

    public String getUniqueNotificationReference() {
        return uniqueNotificationReference;
    }

    public String getClientSessionId() {
        return clientSessionId;
    }
}

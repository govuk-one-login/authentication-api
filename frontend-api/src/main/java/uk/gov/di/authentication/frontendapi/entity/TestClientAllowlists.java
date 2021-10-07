package uk.gov.di.authentication.frontendapi.entity;

import java.util.List;

public final class TestClientAllowlists {
    private static final List ALLOW_LIST_EMAIL =
            List.of(
                    "simulate-delivered@notifications.service.gov.uk",
                    "simulate-delivered-2@notifications.service.gov.uk",
                    "simulate-delivered-3@notifications.service.gov.uk",
                    "temp-fail@simulator.notify",
                    "perm-fail@simulator.notify");

    public static boolean emailAllowlistContains(String email) {
        return ALLOW_LIST_EMAIL.contains(email);
    }
}

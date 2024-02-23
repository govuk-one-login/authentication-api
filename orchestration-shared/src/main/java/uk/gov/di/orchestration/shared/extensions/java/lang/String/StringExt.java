package uk.gov.di.orchestration.shared.extensions.java.lang.String;

import manifold.ext.rt.api.Extension;
import manifold.ext.rt.api.This;

import java.util.Objects;

@Extension
public class StringExt {
    public static boolean isNullOrEmpty(@This String str) {
        return Objects.isNull(str) || str.isEmpty();
    }
}

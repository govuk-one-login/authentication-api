package uk.gov.di.orchestration.shared.extensions.java.lang.Object;

import manifold.ext.rt.api.Extension;
import manifold.ext.rt.api.This;

import java.util.Objects;

@Extension
public class ObjectExt {
    public static boolean isNull(@This Object obj) {
        return Objects.isNull(obj);
    }
}

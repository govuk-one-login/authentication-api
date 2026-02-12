package uk.gov.di.authentication.userpermissions.entity;

public record IndefinitelyLockedOutData(ForbiddenReason forbiddenReason, int attemptCount) {}

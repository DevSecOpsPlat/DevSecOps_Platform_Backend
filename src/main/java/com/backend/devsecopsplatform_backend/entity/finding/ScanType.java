package com.backend.devsecopsplatform_backend.entity.finding;

public enum ScanType {
    CODE,
    IMAGE,
    DEPENDENCIES,
    INFRASTRUCTURE,
    DAST,

    // Extensions pour supporter la centralisation "findings" multi-stages
    SAST,
    SCA,
    SECRETS,
    CONTAINER,
    IAC,
    LICENSE,
    QUALITY
}

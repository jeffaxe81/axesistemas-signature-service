package com.axesistemas.signature.crypto.pades;

public record PadesEvidence(
    int signatureCount,
    int validSignatureCount,
    boolean cryptographicIntegrity,
    String signatureFormat,
    String dssIndication
) {}

export type TrustMode = "fake" | "sandbox" | "production";

export type SignatureLevel = "simple" | "advanced" | "qualified";

export type SignatureFormat =
  | "pades"
  | "cades"
  | "xades"
  | "xmldsig"
  | "detached"
  | "asic"
  | "jades"
  | "proprietary";

export type ProviderKind =
  | "identity"
  | "consent"
  | "signing"
  | "validation"
  | "timestamp";

export type ProviderDescriptor = {
  id: string;
  version: string;
  kind: ProviderKind;
  trustMode: TrustMode;
  signatureLevels: SignatureLevel[];
  signatureFormats: SignatureFormat[];
};

import { expect, it } from "vitest";
import { transitionParticipantStatus } from "./participant.js";

it("permite autenticar, consentir e assinar um participante", () => {
  expect(transitionParticipantStatus("invited", "authenticated")).toBe("authenticated");
  expect(transitionParticipantStatus("authenticated", "consented")).toBe("consented");
  expect(transitionParticipantStatus("consented", "signed")).toBe("signed");
});

it("não permite consentir diretamente a partir de pending", () => {
  expect(() => transitionParticipantStatus("pending", "consented")).toThrow(
    "INVALID_PARTICIPANT_TRANSITION"
  );
});

it("não permite signed voltar para pending", () => {
  expect(() => transitionParticipantStatus("signed", "pending")).toThrow(
    "INVALID_PARTICIPANT_TRANSITION"
  );
});

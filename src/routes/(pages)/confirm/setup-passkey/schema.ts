import { m } from "$i18n/messages";
import { z } from "zod";

export const formSchema = z
  .object({
    userId: z.string().min(3),
    email: z.string().email(m["form.errors.email"]()),
    type: z.enum(["passkey", "passphrase"]).default("passkey"),
    // Passkey-only fields
    id: z.string().optional(),
    attestationObjectBase64: z.string().optional(),
    clientDataJSONBase64: z.string().optional(),
    challenge: z.string().optional(),
    // Passphrase-only fields
    passphrase: z.string().optional(),
  })
  .superRefine((data, ctx) => {
    if (data.type === "passphrase") {
      if (!data.passphrase || data.passphrase.length < 30) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: m["form.errors.passphrase"](),
          path: ["passphrase"],
        });
      }
    } else if (data.type === "passkey") {
      if (
        !data.id ||
        data.id.length < 3 ||
        !data.attestationObjectBase64 ||
        !data.clientDataJSONBase64 ||
        !data.challenge ||
        data.challenge.length < 20
      ) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Passkey data missing",
          path: ["id"],
        });
      }
    }
  });

export type FormSchema = typeof formSchema;

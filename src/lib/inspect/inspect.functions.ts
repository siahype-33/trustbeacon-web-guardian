import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";

const inputSchema = z.object({
  url: z.string().trim().min(1, "Enter a website address").max(2048, "Address is too long"),
});

export const inspectDomain = createServerFn({ method: "POST" })
  .inputValidator((data: unknown) => inputSchema.parse(data))
  .handler(async ({ data }) => {
    const { runInspection } = await import("./inspect.server");
    return runInspection(data.url);
  });

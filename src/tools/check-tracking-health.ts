import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/server";
import type { PlausibleClient, PlausibleResponse } from "../plausible.js";
import { reportToolError } from "../errors.js";
import { recordMcpClientInfo } from "../mcp-telemetry.js";
import {
  siteIdSchemaFor,
  dateRangeSchema,
  buildGoalFilter,
} from "../schemas.js";
import { resolveSiteId } from "./get-timeseries.js";

const trackingHealthOutputSchema = z.object({
  goal: z.string(),
  period: z.string(),
  visitors: z.number(),
  goal_events: z.number(),
  conversion_rate: z.number().nullable(),
  status: z.enum(["healthy", "event_missing", "no_traffic", "low_signal"]),
});

function metricAt(response: PlausibleResponse, index: number): number | null {
  const value = response.results[0]?.metrics[index];
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

export function register(
  server: McpServer,
  client: PlausibleClient,
  defaultSiteId?: string
) {
  server.registerTool(
    "check_tracking_health",
    {
      title: "Check Form Tracking Health",
      description:
        "Check whether site traffic is present but the monitored Plausible goal has disappeared. Defaults to the ticket_form_submit goal.",
      annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: true },
      outputSchema: trackingHealthOutputSchema,
      inputSchema: z.object({
        site_id: siteIdSchemaFor(defaultSiteId),
        date_range: dateRangeSchema.default("24h"),
        goal: z.string().max(1024).default("ticket_form_submit"),
        minimum_visitors: z.number().int().nonnegative().default(20),
      }),
    },
    async (args, ctx) => {
      recordMcpClientInfo(ctx);
      try {
        const siteId = resolveSiteId(args.site_id, defaultSiteId);
        const period = args.date_range ?? "24h";
        const goal = args.goal ?? "ticket_form_submit";
        const [traffic, conversions] = await Promise.all([
          client.query({
            site_id: siteId,
            metrics: ["visitors"],
            date_range: period,
          }),
          client.query({
            site_id: siteId,
            metrics: ["events", "conversion_rate"],
            date_range: period,
            filters: [buildGoalFilter(goal)],
          }),
        ]);

        const visitors = metricAt(traffic, 0) ?? 0;
        const goalEvents = metricAt(conversions, 0) ?? 0;
        const conversionRate = metricAt(conversions, 1);
        const minimumVisitors = args.minimum_visitors ?? 20;
        const status =
          visitors === 0
            ? "no_traffic"
            : visitors < minimumVisitors
              ? "low_signal"
              : goalEvents === 0
                ? "event_missing"
                : "healthy";

        const result = {
          goal,
          period,
          visitors,
          goal_events: goalEvents,
          conversion_rate: conversionRate,
          status,
        };

        return {
          content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }],
          structuredContent: result,
        };
      } catch (error) {
        const message = reportToolError(error, "check_tracking_health");
        return {
          content: [{ type: "text" as const, text: `Error: ${message}` }],
          isError: true,
        };
      }
    }
  );
}

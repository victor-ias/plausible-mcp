import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/server";
import type { PlausibleClient, PlausibleResponse } from "../plausible.js";
import { reportToolError } from "../errors.js";
import { recordMcpClientInfo } from "../mcp-telemetry.js";
import {
  siteIdSchemaFor,
  dateRangeSchema,
  goalSchema,
  buildGoalFilter,
} from "../schemas.js";
import { resolveSiteId } from "./get-timeseries.js";

const anomalyMetrics = [
  "visitors",
  "visits",
  "pageviews",
  "events",
  "conversion_rate",
  "bounce_rate",
] as const;

const anomalyOutputSchema = z.object({
  metric: z.string(),
  goal: z.string().nullable(),
  current: z.number().nullable(),
  baseline_values: z.array(z.number()),
  baseline_median: z.number().nullable(),
  absolute_change: z.number().nullable(),
  percent_change: z.number().nullable(),
  direction: z.enum(["up", "down", "flat", "unknown"]),
  status: z.enum(["normal", "warning", "critical", "insufficient_data"]),
});

function firstMetric(response: PlausibleResponse): number | null {
  const value = response.results[0]?.metrics[0];
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

export function median(values: number[]): number | null {
  if (values.length === 0) return null;
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2
    ? sorted[middle]
    : (sorted[middle - 1] + sorted[middle]) / 2;
}

export function register(
  server: McpServer,
  client: PlausibleClient,
  defaultSiteId?: string
) {
  server.registerTool(
    "detect_anomaly",
    {
      title: "Detect Analytics Anomaly",
      description:
        "Compare one current period with 2-8 comparable baseline periods using their median. Use matching weekdays or hours to avoid seasonality. Optionally filter to a goal such as ticket_form_submit.",
      annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: true },
      outputSchema: anomalyOutputSchema,
      inputSchema: z.object({
        site_id: siteIdSchemaFor(defaultSiteId),
        current_period: dateRangeSchema,
        baseline_periods: z
          .array(dateRangeSchema)
          .min(2)
          .max(8)
          .describe("Comparable historical ranges, ideally the same weekday/hour"),
        metric: z.enum(anomalyMetrics).default("events"),
        goal: goalSchema,
        minimum_baseline: z.number().nonnegative().default(10),
        warning_percent: z.number().positive().default(30),
        critical_percent: z.number().positive().default(50),
      }),
    },
    async (args, ctx) => {
      recordMcpClientInfo(ctx);
      try {
        const siteId = resolveSiteId(args.site_id, defaultSiteId);
        const metric = args.metric ?? "events";
        const filters = args.goal ? [buildGoalFilter(args.goal)] : [];
        const ranges = [args.current_period, ...args.baseline_periods];
        const responses = await Promise.all(
          ranges.map((date_range) =>
            client.query({
              site_id: siteId,
              metrics: [metric],
              date_range,
              filters,
            })
          )
        );

        const current = firstMetric(responses[0]);
        const baselineValues = responses
          .slice(1)
          .map(firstMetric)
          .filter((value): value is number => value !== null);
        const baselineMedian = median(baselineValues);

        let absoluteChange: number | null = null;
        let percentChange: number | null = null;
        let direction: "up" | "down" | "flat" | "unknown" = "unknown";
        let status: "normal" | "warning" | "critical" | "insufficient_data" =
          "insufficient_data";

        if (
          current !== null &&
          baselineMedian !== null &&
          baselineMedian >= (args.minimum_baseline ?? 10)
        ) {
          absoluteChange = current - baselineMedian;
          percentChange =
            baselineMedian === 0 ? null : (absoluteChange / baselineMedian) * 100;
          direction =
            absoluteChange > 0 ? "up" : absoluteChange < 0 ? "down" : "flat";
          const magnitude = Math.abs(percentChange ?? 0);
          status =
            magnitude >= (args.critical_percent ?? 50)
              ? "critical"
              : magnitude >= (args.warning_percent ?? 30)
                ? "warning"
                : "normal";
        }

        const result = {
          metric,
          goal: args.goal ?? null,
          current,
          baseline_values: baselineValues,
          baseline_median:
            baselineMedian === null ? null : Math.round(baselineMedian * 100) / 100,
          absolute_change:
            absoluteChange === null ? null : Math.round(absoluteChange * 100) / 100,
          percent_change:
            percentChange === null ? null : Math.round(percentChange * 100) / 100,
          direction,
          status,
        };

        return {
          content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }],
          structuredContent: result,
        };
      } catch (error) {
        const message = reportToolError(error, "detect_anomaly");
        return {
          content: [{ type: "text" as const, text: `Error: ${message}` }],
          isError: true,
        };
      }
    }
  );
}

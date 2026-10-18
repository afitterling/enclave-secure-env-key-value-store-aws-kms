import { ECSClient, ListTasksCommand, DescribeTasksCommand, StopTaskCommand } from "@aws-sdk/client-ecs";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, BatchGetCommand } from "@aws-sdk/lib-dynamodb";
import { taskIdOf } from "../lib/runner.js";

/**
 * Scheduled every 5 minutes. Fargate has no maximum task runtime, so this is
 * what enforces each run's `deadline` — and it stops any runner task that has
 * no run record at all (a launch that died between RunTask and the record),
 * since nothing could have authorized it.
 */

const ecs = new ECSClient({ region: process.env.ENCLAVE_REGION });
const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({ region: process.env.ENCLAVE_REGION }));
const GRACE = 120; // seconds after launch before a record-less task counts as orphaned

export async function handler() {
  const cluster = process.env.RUNNER_CLUSTER!;
  const arns: string[] = [];
  let nextToken: string | undefined;
  do {
    const out = await ecs.send(
      new ListTasksCommand({ cluster, startedBy: "enclave-runner", desiredStatus: "RUNNING", nextToken }),
    );
    arns.push(...(out.taskArns ?? []));
    nextToken = out.nextToken;
  } while (nextToken);

  const now = Math.floor(Date.now() / 1000);
  let stopped = 0;
  for (let i = 0; i < arns.length; i += 100) {
    const chunk = arns.slice(i, i + 100);
    const described = await ecs.send(new DescribeTasksCommand({ cluster, tasks: chunk }));
    const runs = await ddb.send(
      new BatchGetCommand({
        RequestItems: { [process.env.RUN_TABLE!]: { Keys: chunk.map((a) => ({ runId: taskIdOf(a) })) } },
      }),
    );
    const byId = new Map(
      (runs.Responses?.[process.env.RUN_TABLE!] ?? []).map((r) => [r.runId as string, r]),
    );
    for (const task of described.tasks ?? []) {
      const run = byId.get(taskIdOf(task.taskArn!));
      const age = now - Math.floor((task.createdAt?.getTime() ?? Date.now()) / 1000);
      const reason = !run
        ? age > GRACE
          ? "no run record"
          : null
        : (run.deadline as number) <= now
          ? "maximum runtime reached"
          : null;
      if (!reason) continue;
      await ecs.send(new StopTaskCommand({ cluster, task: task.taskArn!, reason: `enclave reaper: ${reason}` }));
      stopped++;
    }
  }
  console.log(JSON.stringify({ msg: "reaper", running: arns.length, stopped }));
}

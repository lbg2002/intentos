/**
 * Compiled ESM Worker for IntentOS Sandboxed AgentRuntime (`@intentos/pi-adapter`).
 * Runs inside Landlock / Bubblewrap with zero TCP network permissions and zero built-in host tools.
 */
import http from "node:http";
import readline from "node:readline";

const pendingTools = new Map();
const cancelledRuns = new Set();

function emitEvent(event) {
  process.stdout.write(JSON.stringify(event) + "\n");
}

function callGatewayUnixSocket(socketPath, runToken, payload) {
  return new Promise((resolve, reject) => {
    const body = Buffer.from(JSON.stringify(payload), "utf8");
    const req = http.request(
      {
        socketPath,
        path: "/v1/chat/completions",
        method: "POST",
        headers: {
          Host: "intentos.gateway",
          "Content-Type": "application/json",
          "Content-Length": body.length,
          "X-IntentOS-Run-Token": runToken,
        },
      },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
        res.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          try {
            const parsed = JSON.parse(text);
            if ((res.statusCode ?? 500) >= 400) {
              const errMsg =
                parsed?.error?.message ?? `Gateway HTTP ${res.statusCode}: ${text}`;
              reject(new Error(errMsg));
            } else {
              resolve(parsed);
            }
          } catch {
            reject(new Error(`Invalid JSON from ModelGateway: ${text}`));
          }
        });
      }
    );
    req.on("error", (err) => reject(err));
    req.write(body);
    req.end();
  });
}

async function handleRun(req) {
  const socketPath = process.env.INTENTOS_GATEWAY_SOCK;
  if (!socketPath) {
    emitEvent({
      event: "run.failed",
      run_id: req.run_id,
      error: "Missing INTENTOS_GATEWAY_SOCK environment variable",
    });
    return;
  }

  emitEvent({ event: "run.started", run_id: req.run_id });

  const systemPrompt = (req.context_blocks ?? [])
    .map((b) => `[${b.label} | taint=${b.taint}]\n${b.content}`)
    .join("\n\n");

  const messages = [
    { role: "system", content: systemPrompt },
    ...(req.history ?? []).map((m) => ({ role: m.role, content: m.content })),
    { role: req.input.role, content: req.input.content },
  ];

  const openaiTools = (req.tools ?? []).map((t) => ({
    type: "function",
    function: {
      name: t.name,
      description: t.description,
      parameters: t.parameters,
    },
  }));

  const maxTurns = Math.min(req.budget?.max_tool_calls ?? 10, 15);
  let toolCallsUsed = 0;

  try {
    for (let turn = 0; turn < maxTurns; turn++) {
      if (cancelledRuns.has(req.run_id)) {
        emitEvent({ event: "run.cancelled", run_id: req.run_id });
        return;
      }

      const completion = await callGatewayUnixSocket(socketPath, req.run_token, {
        model: req.model_id,
        messages,
        tools: openaiTools.length > 0 ? openaiTools : undefined,
      });

      if (completion?.usage) {
        emitEvent({
          event: "usage.updated",
          run_id: req.run_id,
          input_tokens: completion.usage.prompt_tokens ?? 0,
          output_tokens: completion.usage.completion_tokens ?? 0,
        });
      }

      const choice = completion?.choices?.[0];
      const msg = choice?.message;
      if (!msg) {
        throw new Error("Empty choice message returned from ModelGateway");
      }

      const toolCalls = Array.isArray(msg.tool_calls) ? msg.tool_calls : [];
      if (toolCalls.length > 0) {
        messages.push(msg);
        for (const tc of toolCalls) {
          toolCallsUsed += 1;
          if (toolCallsUsed > (req.budget?.max_tool_calls ?? 30)) {
            throw new Error("Exceeded task tool call budget");
          }
          const callId = tc.id ?? `call_${turn}_${toolCallsUsed}`;
          const toolName = tc.function?.name ?? "";
          let parsedArgs = {};
          if (typeof tc.function?.arguments === "string") {
            try {
              parsedArgs = JSON.parse(tc.function.arguments);
            } catch {
              parsedArgs = {};
            }
          } else if (tc.function?.arguments && typeof tc.function.arguments === "object") {
            parsedArgs = tc.function.arguments;
          }

          const resultPromise = new Promise((resolve) => {
            pendingTools.set(callId, { resolve });
          });

          emitEvent({
            event: "tool.requested",
            run_id: req.run_id,
            call_id: callId,
            tool_name: toolName,
            arguments: parsedArgs,
          });

          const toolRes = await resultPromise;
          messages.push({
            role: "tool",
            tool_call_id: callId,
            content: JSON.stringify(toolRes.output),
          });
        }
        continue;
      }

      const finalText = typeof msg.content === "string" ? msg.content : "";
      if (finalText.length > 0) {
        emitEvent({
          event: "message.delta",
          run_id: req.run_id,
          delta: finalText,
        });
      }
      emitEvent({
        event: "run.finished",
        run_id: req.run_id,
        final_message: finalText,
      });
      return;
    }

    emitEvent({
      event: "run.finished",
      run_id: req.run_id,
      final_message: "已达到单次任务工具规划轮数上限。",
    });
  } catch (err) {
    emitEvent({
      event: "run.failed",
      run_id: req.run_id,
      error: err?.message ?? String(err),
    });
  }
}

const rl = readline.createInterface({
  input: process.stdin,
  crlfDelay: Infinity,
});

rl.on("line", (line) => {
  const trimmed = line.trim();
  if (!trimmed) return;
  let msg;
  try {
    msg = JSON.parse(trimmed);
  } catch {
    return;
  }

  if (msg.method === "initialize") {
    emitEvent({
      jsonrpc: "2.0",
      id: msg.id ?? 1,
      result: {
        name: "pi-adapter",
        version: "0.1.0-poc",
        features: ["unix_socket_gateway", "zero_builtin_tools", "taint_context"],
      },
    });
  } else if (msg.method === "run" && msg.params) {
    void handleRun(msg.params);
  } else if (msg.method === "tool_result" && msg.params) {
    const callId = msg.params.call_id;
    const waiter = pendingTools.get(callId);
    if (waiter) {
      pendingTools.delete(callId);
      waiter.resolve({
        is_error: Boolean(msg.params.is_error),
        output: msg.params.output ?? {},
      });
    }
  } else if (msg.method === "cancel" && msg.params?.run_id) {
    cancelledRuns.add(msg.params.run_id);
  }
});

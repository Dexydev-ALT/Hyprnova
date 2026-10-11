// SPDX-License-Identifier: Apache-2.0
// HyprNova :: the AI analyst (implementation).

#include "ai/analyst.hpp"

#include "core/exec.hpp"
#include "core/fd.hpp"
#include "core/log.hpp"

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <system_error>

namespace fs = std::filesystem;

namespace hyprnova::ai {

namespace {

using core::json::Value;

std::string_view kSystemPrompt =
    "You are HyprNova's forensic analyst assistant embedded in a Linux "
    "anti-malware product. You receive EVIDENCE collected on the host: sensor "
    "events, scan verdicts, process lineage, package-integrity results, "
    "network observations. Rules, in strict order:\n"
    "1. Base every statement on the evidence IDs you are given. If evidence is "
    "missing, say exactly what is missing and how to collect it.\n"
    "2. Distinguish OBSERVATIONS from HYPOTHESES. Assign a confidence "
    "(low/medium/high) to each hypothesis and say what would confirm it.\n"
    "3. NEVER claim a scan ran, a file was recovered, or an action was taken "
    "unless the evidence says so. Never invent hashes, paths, or detections.\n"
    "4. You may RECOMMEND actions (allow / keep suspended / quarantine / "
    "block network / deeper memory forensics), but the human operator decides "
    "and executes. Your output never executes anything.\n"
    "5. Be concise: verdict-relevant facts first, then reasoning, then "
    "recommended next steps. Cite evidence IDs like [e12].\n";

}  // namespace

std::string_view AiAnalyst::system_prompt() noexcept { return kSystemPrompt; }

bool AiAnalyst::ready(std::string& why_not) const noexcept {
    if (!cfg_.enabled) {
        why_not = "ai.enabled is false in agent.json (turn it on to consent to "
                  "sending evidence summaries to the provider)";
        return false;
    }
    if (cfg_.api_key.empty()) {
        why_not = "ai.api_key is not set (Groq key: console.groq.com/keys)";
        return false;
    }
    const std::string curl = core::exec::find_in_system_path("curl");
    if (curl.empty()) {
        why_not = "curl not found in the trusted system path";
        return false;
    }
    return true;
}

std::string AiAnalyst::build_user_message(std::string_view question,
                                          const core::json::Value& evidence) noexcept {
    std::string out{"EVIDENCE (JSON, ids are stable):\n"};
    out += evidence.dump();
    out += "\n\nQUESTION: ";
    out += question;
    out += "\n\nAnswer with: VERDICT (benign / suspicious / malicious / "
           "inconclusive), CONFIDENCE, REASONING (citing [eN]), RECOMMENDED "
           "NEXT STEPS.";
    if (out.size() > 60'000) {
        // Hard bound: a consult must never depend on unbounded host state.
        out.resize(60'000);
        out += "\n[...evidence truncated...]";
    }
    return out;
}

std::optional<std::string> AiAnalyst::parse_answer(std::string_view body) noexcept {
    auto v = core::json::parse(body);
    if (!v) return std::nullopt;
    const auto content = v->str("choices.0.message.content");
    if (content.empty()) return std::nullopt;
    return content;
}

AiAnalyst::Consult AiAnalyst::ask(std::string_view question,
                                  const core::json::Value& evidence) noexcept {
    Consult c;
    c.model = cfg_.model;
    const auto started = std::chrono::steady_clock::now();

    std::string why;
    if (!ready(why)) {
        c.error = why;
        return c;
    }

    // ---- build the request body into a 0600 temp file ----------------------
    using core::json::Array;
    using core::json::Object;
    using core::json::Value;
    Object body;
    body["model"] = cfg_.model;
    Array msgs;
    {
        Object sys;
        sys["role"] = std::string("system");
        sys["content"] = std::string(kSystemPrompt);
        msgs.push_back(Value{std::move(sys)});
        Object usr;
        usr["role"] = std::string("user");
        usr["content"] = build_user_message(question, evidence);
        msgs.push_back(Value{std::move(usr)});
    }
    body["messages"] = Value{std::move(msgs)};
    body["temperature"] = 0.1;
    body["max_tokens"] = static_cast<std::int64_t>(cfg_.max_answer_tokens);

    const std::string req_path = cfg_.request_temp_path;
    {
        std::ofstream out{req_path, std::ios::binary | std::ios::trunc};
        if (!out) {
            c.error = std::format("cannot stage request at {}", req_path);
            return c;
        }
        out << Value{std::move(body)}.dump();
    }
    if (!core::fsx::set_mode(req_path, 0600))
        SWARN("ai", "could not chmod 0600 the staged request {}: it keeps its creation mode",
              req_path);

    const std::string curl = core::exec::find_in_system_path("curl");
    core::exec::Options opts;
    opts.timeout = cfg_.timeout;
    opts.max_output_bytes = 1 << 20;
    const auto res = core::exec::run(
        curl,
        {"-sS", "--max-time", std::to_string(cfg_.timeout.count() - 2),
         "-H", "Content-Type: application/json",
         "-H", "Authorization: Bearer " + cfg_.api_key,
         "--data", "@" + req_path,
         "https://api.groq.com/openai/v1/chat/completions"},
        opts);
    std::error_code ec;
    fs::remove(fs::path{req_path}, ec);

    c.elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started);

    if (!res.spawned) {
        c.error = res.error.empty() ? std::string("failed to spawn curl") : res.error;
        return c;
    }
    if (res.timed_out) {
        c.error = std::format("provider timed out after {}s",
                              std::chrono::duration_cast<std::chrono::seconds>(cfg_.timeout).count());
        return c;
    }
    if (res.exit_code != 0) {
        c.error = std::format("curl exit {}: {}", res.exit_code,
                              res.err.substr(0, 200));
        return c;
    }
    // Groq errors come back as {"error": {...}} with HTTP 200 occasionally.
    if (res.out.find("\"error\"") != std::string::npos) {
        auto v = core::json::parse(res.out);
        const std::string msg = v ? v->str("error.message") : std::string("(unparseable)");
        if (!msg.empty()) {
            c.error = std::format("provider error: {}", msg);
            return c;
        }
    }
    if (const auto answer = parse_answer(res.out)) {
        c.ok = true;
        c.answer = *answer;
        return c;
    }
    c.error = "could not parse the provider response";
    return c;
}

}  // namespace hyprnova::ai

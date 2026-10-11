// SPDX-License-Identifier: Apache-2.0
// HyprNova :: the AI analyst (Module 9).
//
// Groq-hosted LLM as a FORENSIC ASSISTANT, never a decider. The contract, in
// order of importance:
//
//   1. The model sees EVIDENCE we collected (events, verdicts, lineage,
//      package/integrity state) -- never guesses, never the network on its own,
//      never a shell. It may RECOMMEND; only the operator clicks.
//   2. It can NEVER directly trigger quarantine/kill/shred. Outputs are text
//      that a human reads; the answer endpoints require the human's own input.
//   3. Consent is explicit: ai.enabled + ai.api_key in agent.json. Without a
//      key the module is inert and everything else works offline.
//   4. Every consult (prompt size, answer, latency) is journalled to
//      state_dir/ai-consults.ndjson so investigations stay auditable.
//
// Transport is the hardened exec layer + system curl (same policy as the
// VirusTotal path): no bundled HTTP client, no shell, absolute binary path,
// hard timeout, request body staged in a 0600 temp file.

#pragma once

#include "core/config.hpp"
#include "core/json.hpp"

#include <optional>
#include <string>
#include <string_view>

namespace hyprnova::ai {

class AiAnalyst {
public:
    explicit AiAnalyst(const core::AiConfig& cfg) noexcept : cfg_(cfg) {}

    struct Consult {
        bool ok{false};
        std::string answer;
        std::string model;
        std::chrono::milliseconds elapsed{};
        std::string error;
    };

    /// Ready = enabled + key + curl present. The bridge surfaces this so the
    /// console can show "AI: on/off (why)" instead of a dead button.
    [[nodiscard]] bool ready(std::string& why_not) const noexcept;

    /// The system prompt: role, evidence-only rule, and the hard prohibition on
    /// authorising destructive actions. Fixture-tested.
    [[nodiscard]] static std::string_view system_prompt() noexcept;

    /// Send one consult. `evidence` is a JSON object built by the caller (the
    /// bridge): question context, recent events, pending decision, verdicts.
    [[nodiscard]] Consult ask(std::string_view question,
                              const core::json::Value& evidence) noexcept;

    /// Extract choices[0].message.content from a Groq response. Fixture-tested.
    [[nodiscard]] static std::optional<std::string> parse_answer(
        std::string_view body) noexcept;

    /// Compact the evidence into the user-message text (bounded, deterministic).
    [[nodiscard]] static std::string build_user_message(
        std::string_view question, const core::json::Value& evidence) noexcept;

private:
    core::AiConfig cfg_;
};

}  // namespace hyprnova::ai

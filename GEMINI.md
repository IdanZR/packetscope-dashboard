# Gemini integration

PacketScope supports **Gemini 3.5 Flash-Lite** through Google's official REST API. **AI settings** lets you choose Gemini, select another configured model, or keep using the free offline **Local Qwen** option. Gemini requires internet access and is subject to your Google account's quota, limits and pricing. No billing settings are changed by this application.

## Credentials

Enter a key in **AI settings → API key for this session**. This is a password field with no prefilled key. The override stays in server-side session memory and is excluded from exports. You can instead set the `GEMINI_API_KEY` environment variable before running Streamlit. Never add a real key to Python source, README files, screenshots or a submission ZIP.

The running development server uses an in-memory environment credential. No credential file is retained. On Windows, `start_gemini.bat` installs the core dependencies if needed, prompts for the key without echoing it, then launches Streamlit with the key in process memory. Closing the server discards that process credential. You can also use the session field or provide GEMINI_API_KEY through your own environment setup.

The source packager excludes secrets files, environment files, encrypted credential files and model data. It also checks for the currently configured key before writing the ZIP. Reports contain the provider/model name and interpreted query, never the key.

## What is sent

Only when you click **Ask Gemini** or the cloud validation button, the application sends your question, extracted request/transaction totals, selection IDs and a catalog of at most 12 HTTP transaction summaries to `generativelanguage.googleapis.com` over HTTPS. Summaries contain method, Host, URI, status and matching state; strings are limited to 160 characters. Your PCAP file, raw request/response bytes, headers and bodies are not sent. Host/URI metadata can itself contain private information, so choose Local Qwen for offline-only analysis.

Gemini returns a JSON query conforming to `PLAN_SCHEMA`. Python validates selectors, computes the answer over all parsed transactions and attaches original frame/timestamp evidence. Switching providers does not remove these checks. Unsupported questions, missing responses and unsafe matches remain explicit. The AI does not decrypt HTTPS.

## Verification and service errors

The key was verified against Google's model listing, and six synthetic reference questions passed using real Gemini calls. See `validation_gemini.json`. The historical local Qwen reports remain separate in `validation_ai.json` and `validation_ai_before_fix.json`; their errors are documented in `AI_VALIDATION.md`.

Requests have a 45-second timeout, a 2 MB response limit, no redirects and at most one retry for HTTP 5xx service errors. API keys are sent in the `x-goog-api-key` header, never in URL parameters. Authentication, quota and service errors are summarized without displaying vendor response text or credentials. There is no automatic provider fallback or background generation at startup.

Official references: [REST generateContent](https://ai.google.dev/api/generate-content), [structured outputs](https://ai.google.dev/gemini-api/docs/structured-output), [Gemini 3.5 Flash-Lite](https://aistudio.google.com/docs/models/gemini-3.5-flash-lite), [Google pricing](https://aistudio.google.com/docs/pricing).

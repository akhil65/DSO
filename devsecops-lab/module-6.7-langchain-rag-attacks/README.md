# Module 6.7 — LangChain RAG Pipeline Attacks

> Module 6.6 demonstrated semantic injection using raw components and mock fallbacks. This module repeats the same attacks using the full production LangChain stack — real ChromaDB vector search, real OllamaEmbeddings, real LCEL chains, and real ChatOllama responses. The goal is to see what the attacks look like in actual running code, not simulations.

---

## Real-World Context

Module 6.6 showed that semantic injection bypasses per-message scanning entirely — the payload arrives through the knowledge base, the conversation history, or a data field, and the scanner never sees it. This module proves that the same gaps exist in the specific libraries an engineering team would actually deploy: LangChain LCEL, LangGraph agents, ChromaDB, and OllamaEmbeddings.

**Why this matters at the product level:** When an organisation ships an AI feature today — a customer support chatbot, a compliance assistant, a document summariser — it is almost always built on LangChain or an equivalent framework (LlamaIndex, Haystack, Vertex AI chains). The abstractions are different from raw Python, but the attack surfaces are the same: wherever untrusted content reaches the LLM's context window without being scanned, injection is possible. Module 6.7 maps the theoretical gaps from 6.6 to the concrete library calls that create them.

**Who owns this in a real org:** Three teams share this problem space. The **ML platform team** owns the LangChain pipeline — chain composition, retriever configuration, embedding model selection — and is responsible for scanning at each stage boundary. The **AppSec team** owns the threat model: which data sources feed the pipeline, which data stores can an external party write to (the "contributor-is-attacker" surface), and whether any tool the agent calls has write or send privilege. The **red team** exercises the attack in staging: crafting payload documents, poisoned CSV rows, and CRM field injections against the real running pipeline.

**The LCEL pipe operator is an attack surface map:** Every `|` in a LangChain chain is a data flow boundary. `retriever | format_docs | prompt | llm | parser` means: the retriever's output (retrieved documents) flows into format_docs, then into the prompt, then into the LLM, then into the parser. LLM Guard placed before the retriever scans only one of those five stages. An attacker who controls retrieved documents, format functions, or upstream data sources controls all downstream stages. The pipe makes the trust propagation explicit — and exploitable.

**Maturity model across modules:**
- **Module 6 (baseline):** input scanner on user message only
- **Module 6.6:** established why that is insufficient — three channels route around it
- **Module 6.7 (this module):** demonstrates the same three gaps in real LangChain code; introduces the per-trust-boundary scanning pattern

```
                ┌─────────────────────────────────────────────────────┐
                │  Production LangChain pipeline — scan placement     │
                │                                                      │
  user ─► [SCAN A] ─► retriever ─► [SCAN B] ─► format ─► prompt      │
                │                                                      │
         data store ─► CSVLoader ─► [SCAN C] ─► TextSplitter ─► Chroma│
                │                                                      │
           CRM/API ─► tool output ─► [SCAN D] ─► agent scratchpad     │
                │                                                      │
                │  LLM ─► [SCAN E] ─► parser ─► user                  │
                └─────────────────────────────────────────────────────┘

  Scan A: what Module 6 implemented
  Scan B: what 6.7.1 demonstrates is missing
  Scan C: what 6.7.3 demonstrates is missing
  Scan D: what 6.7.2 demonstrates is missing
  Scan E: output scanning — catches credential leakage at the exit point
```

**Lab vs real world:** In this module, ChromaDB runs on localhost, the LLM is llama3.2:1b in a Docker container, and the "CRM" is a Python dict. In production, ChromaDB is replaced by Pinecone, Weaviate, or pgvector; ChatOllama is replaced by the OpenAI or Anthropic API; the CRM is Salesforce, HubSpot, or ServiceNow. The injection surfaces are identical — only the scale differs. More contributors to the vector store, more external data feeds, more tools with higher privilege.

---

## Key Concepts — Plain Language

These explainers translate the technical terms in this module into what they actually mean for a product team or security engineer encountering them in the field.

**What "LangChain LCEL pipeline" means in an organisation**

When an engineering team builds an AI product — a customer support bot, a compliance assistant, a code review tool — they almost never call the LLM directly. They assemble a pipeline: fetch relevant documents from a knowledge base, format them, add a system prompt, call the LLM, parse the output. LangChain LCEL is the library that wires those stages together with the pipe operator (`|`). Every major AI product team uses either LangChain or a near-identical pattern (LlamaIndex, Haystack, Vertex AI chains). Module 6.7 is not an academic exercise — it's the exact architecture a team would push to production.

**What "OllamaEmbeddings + ChromaDB" means in an organisation**

Embedding generation and vector search is how RAG actually works at scale. A company that can't afford GPT-4 for every query will run a local embedding model (Ollama, sentence-transformers) to convert documents to vectors once, store them in a vector database (ChromaDB, Pinecone, Weaviate), and retrieve the most relevant ones at query time. The security implication is direct: whoever controls what goes into the vector database controls what context the LLM sees. In 6.7.1, `doc_006` is that attacker-controlled document — a policy document that any contributor to the shared knowledge base could have uploaded.

**What "cosine similarity is embedding-model dependent" means practically**

The poisoned document not landing in the top-2 results during some runs is not a security control — it's noise. A real attacker crafts their payload document to maximise cosine similarity to the expected queries. They do this by wrapping the injection payload in legitimate-looking content ("AcmeCorp Refund Policy Update — Internal") so the embedding model scores it as highly relevant to "What is your refund policy?" The closer the disguise to real content, the more reliably it is retrieved. The exercise still demonstrates the architectural gap — whether the poisoned doc is retrieved or not, the scanner score on the user query is identical either way.

**What "LangGraph ReAct agent" means in an organisation**

An "agent" is the shift from LLMs that produce text to LLMs that take actions. A ReAct agent decides in a loop: what tool should I call next, given everything I've observed so far? In production this means: call the CRM API, read the ticket, look up the customer, send the email — all autonomously. The blast radius scales directly with tool privilege. An agent with read-only access leaks data; an agent with write access modifies records; an agent with send access exfiltrates. The `notes` field injection in 6.7.2 demonstrates that any text field in any system the agent reads is a potential attack surface — CRM, ERP, ticketing systems, HR platforms, log files.

**What "DeBERTa logits vs probabilities" means to an ML engineer**

DeBERTa is a transformer model fine-tuned as a binary classifier (injection / not-injection). Its final layer outputs raw logits — unbounded real numbers — not probabilities. A logit of `−1.000` means the model is confidently in the "not injection" class; a logit of `1.000` means the opposite. The threshold is `score >= 0.5`, not `score >= 0.0`. Most engineers first encounter the negative scores and assume the scanner is broken — as happened here in the early mock exercises where `0.001` was hardcoded to simulate "clean." The real DeBERTa scores being negative for clean input is correct behaviour, confirmed across all three 6.7 exercises.

**What "silent except: pass" means to a security engineer**

This is one of the most common bugs in production AI security tooling. A library updates its API — in this case, LangChain 0.2+ changed `scores` from a dict to a float, so `scores.get()` started raising `AttributeError`. The `except` block swallowed it silently and returned a hardcoded `0.001`. The system appeared to work. Monitoring showed no errors. The scanner appeared to be running. But it wasn't — it was returning a safe value on every call regardless of the input. The fix is always the same: `except Exception as e: print(f"[warn] {e}")` so the failure is visible in logs and alerting before it reaches production.

**The module arc — one sentence per module**

- **Module 6.5** — attacking the model itself: weights, training data, inference evasion
- **Module 6.6** — attacking the pipeline around the model: scanner placement gaps (scanner never sees the poisoned doc, the persona accumulation, or the data field)
- **Module 6.7** — attacking a real production stack (LangChain + ChromaDB + LangGraph) using those same gaps, with real DeBERTa inference confirming the gap at every stage

---

## ML Terms Addendum — LangChain & Agent Concepts for Security Practitioners

**LCEL (LangChain Expression Language)** — a pipe-based composition syntax for assembling LLM pipelines. `A | B | C` means the output of A is passed as the input to B, and so on. A typical RAG chain: `retriever | format_docs | prompt | llm | StrOutputParser()`. Security implication: injection that enters at any stage (retriever output, format function, prompt template) propagates to all downstream stages automatically.

**OllamaEmbeddings** — a LangChain component that calls the Ollama Docker server to convert text to high-dimensional numeric vectors (4096 dimensions with llama3.2:1b). The same Docker service that runs the chat LLM also handles embedding requests. Security implication: the quality of the embedding model determines retrieval precision. A weak embedding model cannot distinguish "legitimate refund policy" from "attacker's fake refund policy update" — making poisoned document retrieval easier. A stronger model makes more semantically precise distinctions.

**Cosine similarity** — the metric ChromaDB uses to rank retrieved documents. It measures the angle between two vectors: 0° = identical meaning, 90° = unrelated. The retriever returns the `k` documents with the smallest angle to the query vector. Security implication: an attacker who titles their poisoned document to match the expected query ("AcmeCorp Refund Policy Update — Internal") achieves high cosine similarity and reliable retrieval. The similarity metric does not evaluate trustworthiness — only semantic proximity.

**LangGraph ReAct agent** — an agent built as a state machine where the LLM iterates through a Reason-Act-Observe loop. At each step, the LLM reads the full message history (including all prior tool outputs), decides what to do next, and either calls a tool or produces a final answer. LangGraph replaced LangChain's `AgentExecutor` in LangChain 1.x. Security implication: every tool output the agent has ever received is in the message history and readable on every subsequent LLM call. A poisoned tool output from step 1 influences every subsequent decision — not just step 2.

**Tool privilege and blast radius** — the set of real-world actions available to an agent through its tools. A read-only tool (CRM lookup, document search) enables information leakage on injection. A write tool (send email, update record, call API) enables data exfiltration or system modification. The blast radius of a successful injection equals the maximum damage achievable by the highest-privilege tool the agent holds. Security implication: principle of least privilege applies to agent tools exactly as it does to service accounts — grant only what the specific task requires, not what might be convenient.

**CSVLoader → Document pipeline** — LangChain's standard path for ingesting tabular data. `CSVLoader(file_path).load()` reads each CSV row and creates one `Document` object with `page_content` (the row's fields as a formatted string) and `metadata` (source filename, row number). The Document then flows through `RecursiveCharacterTextSplitter` → `OllamaEmbeddings` → `Chroma.from_documents()`. Security implication: a poisoned value in any field of any row becomes part of `page_content`, which flows through every subsequent stage without re-sanitisation. The CSV file format offers no structural separation between data and instructions.

**DeBERTa raw logits vs probabilities** — LLM Guard's `PromptInjectionV2` scanner uses a DeBERTa transformer fine-tuned as a binary classifier (injection / not-injection). Its output is a raw logit from the model's final classification layer, not a probability. Logits are unbounded real numbers: a large negative value means confidently NOT injection; a large positive value means confidently injection. The passing threshold is `score >= 0.5`. A score of `−1.000` for a clean user query is the model operating correctly — it is not a malfunction or a scanner failure. This is why the exercises show negative scores as `🟢 PASSED`.

**Silent exception handling as a security failure mode** — the original `except Exception: pass` pattern in 6.7.2's `scan_input()` function is an example of how API changes become invisible security regressions. When `scores.get()` raised `AttributeError` (because the LangChain API changed the return type from dict to float), the exception was swallowed and the function returned a hardcoded `0.001` — making a broken scanner appear healthy. In a production pipeline, this would pass every injection silently. The fix — `except Exception as e: print(f"[warn] {e}")` — makes the failure visible in logs and monitoring.

---

## Prerequisites

Modules 6, 6.5, and 6.6 complete. You need:

- `llm-guard-env` conda environment (from Module 6)
- Ollama running in Docker (from Module 6)
- A pulled LLM model (llama3.2:1b minimum; llama3.1:8b recommended for higher injection compliance)

---

## Setup

### Step 1 — Start Ollama

```bash
cd devsecops-lab/module-6-ai-security
docker compose up -d ollama

# Verify it's healthy (wait ~30s after start)
docker compose exec ollama ollama list

# Pull the model if not already present
docker compose exec ollama ollama pull llama3.2:1b
```

### Step 2 — Install Python dependencies

```bash
conda activate llm-guard-env
pip install langchain langchain-ollama langchain-chroma langchain-community langchain-text-splitters chromadb
```

### Step 3 — Run exercises

```bash
cd devsecops-lab/module-6.7-langchain-rag-attacks

# Exercise 1 — LangChain RAG chain poisoning
python exercises/6.7.1-langchain-rag-poisoning.py

# Exercise 2 — LangChain agent tool injection
python exercises/6.7.2-langchain-agent-injection.py

# Exercise 3 — LCEL chain document injection
python exercises/6.7.3-lcel-chain-injection.py
```

### Environment variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `OLLAMA_BASE` | `http://localhost:11434` | Ollama API base URL |
| `OLLAMA_MODEL` | `llama3.2:1b` | Model for LLM + embeddings |

To use a different model:
```bash
OLLAMA_MODEL=llama3.1:8b python exercises/6.7.1-langchain-rag-poisoning.py
```

---

## How this differs from Module 6.6

| Aspect | Module 6.6 (raw components) | Module 6.7 (LangChain) |
|--------|-----------------------------|------------------------|
| Embeddings | `sentence_transformers` or keyword fallback | `OllamaEmbeddings` (same Ollama server) |
| Vector search | ChromaDB direct API | `langchain-chroma` Chroma wrapper |
| LLM | mock responses | `ChatOllama` — real inference |
| LLM Guard scores | simulated `if/else` | real DeBERTa inference |
| RAG pipeline | manual `retrieve → call_llm` | LCEL: `retriever \| format \| prompt \| llm \| parser` |
| Agent | not used | `create_react_agent` + `AgentExecutor` with real tool calls |
| Document loading | inline Python dicts | `CSVLoader` → `TextSplitter` → Chroma |

---

## What is LangChain?

LangChain is a framework for building LLM applications. Its key abstractions:

**LCEL (LangChain Expression Language)** — a pipe-based composition syntax. `A | B | C` means the output of A becomes the input of B, and so on. A typical RAG chain looks like:

```python
chain = (
    {"context": retriever | format_docs, "question": RunnablePassthrough()}
    | prompt
    | llm
    | StrOutputParser()
)
response = chain.invoke("What is your refund policy?")
```

**Retriever** — an abstraction over a vector store. `vectorstore.as_retriever()` returns an object that takes a query string and returns a list of `Document` objects sorted by semantic similarity.

**Document loaders** — components that read external data and convert it into `Document` objects with `page_content` and `metadata`. `CSVLoader` reads a CSV file; each row becomes a Document. `WebBaseLoader` fetches a URL. `PDFMinerLoader` reads a PDF.

**Text splitters** — break large Documents into chunks that fit within the LLM's context window. `RecursiveCharacterTextSplitter` splits on paragraph/sentence boundaries.

**Agents** — an LLM that iteratively decides which tools to call. Uses the ReAct (Reason + Act) loop: Think about what to do → call a tool → observe the result → repeat until done.

**OllamaEmbeddings** — converts text to vectors using the Ollama server. The same Docker service used for LLM inference can also serve embedding requests on the same port.

---

## MITRE ATLAS Threat Matrix

| ATLAS ID | Technique | Exercise |
|----------|-----------|----------|
| AML.T0054.002 | Indirect Prompt Injection via Retrieval | 6.7.1, 6.7.3 |
| AML.T0054.002 | Indirect Injection via Agent Tool Output | 6.7.2 |
| AML.T0054.003 | Prompt Injection via Third-Party Content | 6.7.3 |
| AML.T0051    | LLM Data Leakage (credential exposure) | 6.7.1, 6.7.2, 6.7.3 |
| T1567        | Exfiltration Over Web Service (via agent tool) | 6.7.2 |

---

## Exercise 6.7.1 — LangChain RAG Chain Poisoning

**Threat:** AML.T0054.002 — Indirect Prompt Injection via Retrieval
**Stack:** OllamaEmbeddings + Chroma + LCEL + ChatOllama + LLM Guard

This is the Module 6.6 RAG poisoning attack rebuilt with the full LangChain stack. The difference: `OllamaEmbeddings` computes real semantic vectors for both the documents and the query. When the attacker's poisoned document is semantically close to refund-policy queries (which it is — it's titled "Refund Policy Update"), Chroma's cosine similarity search ranks it highly. The LLM then receives the embedded instruction in its context and responds to the user with a credential-harvesting prompt.

```bash
python exercises/6.7.1-langchain-rag-poisoning.py
```

**What to watch for:**
- The Ollama server embedding each document during `Chroma.from_documents()` — you'll see latency as it generates vectors
- The retrieval step: whether `doc_006` (poisoned) appears in the top-2 results depends on how close its vector is to the query
- The LLM's response changing from a legitimate refund answer to the injected content (if the poisoned doc is retrieved)
- LLM Guard scoring the same value on the user query in both Phase 2 and Phase 4 — the score never changes regardless of what Chroma retrieves

**Score format note:** LLM Guard's DeBERTa classifier returns raw logits. A negative score (e.g., `-1.000`) means the model is confident the text is NOT injection — this is normal for benign inputs. The threshold for blocking is `score >= 0.5`. Mock exercises used `0.001`; real DeBERTa inference typically returns values in the range `[-2.0, +2.0]`.

**Note on retrieval (llama3.2:1b):** The poisoned document may or may not land in the top-k Chroma results depending on the embedding model's vector space. With `llama3.2:1b` embeddings, `doc_006` sometimes ranks below the clean policy documents. This is embedding-quality dependent, not a security control. A real attacker would title the document to maximise semantic overlap with the target query. The script now prints a note if the poisoned doc is not retrieved and still runs the LLM call to show the architectural gap.

**Note on model compliance:** `llama3.2:1b` has safety training that may partially resist the injection even when the poisoned doc is retrieved. Use `llama3.1:8b` for higher injection compliance.

---

## Exercise 6.7.2 — LangChain Agent Tool Injection

**Threat:** AML.T0054.002 — Indirect Injection + T1567 — Exfiltration via Tool
**Stack:** ChatOllama + `langgraph.prebuilt.create_react_agent` + custom tools + LLM Guard

This exercise introduces LangChain agents: an LLM that uses tools in a ReAct loop to answer questions. The agent has two tools — `lookup_customer_data` (reads a CRM) and `send_support_email` (sends email). The attacker poisons a CRM record so that when the agent queries it, the tool returns injected instructions alongside the customer data. The instructions tell the agent to call `send_support_email` to an attacker-controlled address with the system's internal API key.

**API note:** `AgentExecutor` was removed in LangChain 1.x. This exercise uses `langgraph.prebuilt.create_react_agent` — the current standard (requires `pip install langgraph`).

```bash
python exercises/6.7.2-langchain-agent-injection.py
```

**What to watch for:**
- The `[TOOL CALLED]` and `[TOOL OUTPUT]` lines showing the agent's tool calls in real time
- The LangGraph ReAct trace: the agent calls `lookup_customer_data`, reads the returned record, and decides next steps
- Whether the agent processes the injected `notes` field instruction
- Whether it decides to call `send_support_email` to the attacker address
- LLM Guard scoring `< 0.5` (PASSED) on the user request — the scanner never saw the tool output
- The defence demo at the end: scanning the C003 tool output directly yields score `1.000` (BLOCKED — maximum confidence injection signal)

**Observed behaviour with llama3.2:1b:** The agent correctly calls `lookup_customer_data` and reads the poisoned notes field (visible in `[TOOL OUTPUT]` trace). The model's safety guardrails prevent it from calling `send_support_email` to the attacker address — it even flags the injected notes as "for compliance purposes only." With `llama3.1:8b` or a less safety-tuned model the exfiltration succeeds. The architectural gap (unscanned tool output) is confirmed by the defence demo scoring `1.000` BLOCKED.

**Why agents amplify injection risk:** A chatbot that's injected produces unexpected *words*. An agent that's injected takes unexpected *actions* — sending emails, calling APIs, writing files. The blast radius is proportional to the tools available to the agent.

---

## Exercise 6.7.3 — LCEL Chain Document Injection

**Threat:** AML.T0054.003 — Injection via Third-Party Content
**Stack:** CSVLoader + TextSplitter + Chroma + LCEL + ChatOllama + defence demo

This exercise attacks three surfaces unique to LCEL document-processing pipelines. Attack A loads a CSV with a poisoned row using `CSVLoader` — the standard LangChain data ingestion path for spreadsheets. The poisoned row becomes a `Document`, gets split, embedded, and retrieved, and its injected instruction reaches the LLM through the LCEL chain's `context` variable. Attack B demonstrates metadata injection: if the format function includes `metadata["source"]` (the filename) in the prompt, an attacker-controlled filename becomes an injection vector. Attack C explains output parser bypass via structurally valid but semantically malicious LLM output.

```bash
python exercises/6.7.3-lcel-chain-injection.py
```

**What to watch for:**
- CSVLoader converting CSV rows to LangChain Documents (5 docs from 5 CSV rows)
- The LCEL pipeline diagram printed at runtime showing the exact data flow
- In the poisoned run, notice which vendors appear in the LLM response versus the clean run — the poisoned V003 row is retrieved but its compliance data is replaced by the injection payload, so the model summarises other vendors instead
- The defence demo: scanning all 5 documents before chain assembly — clean set produces 0 false positives, poisoned set quarantines exactly 1 doc (V003/DataCore, score `1.000` BLOCKED)
- User query score remains `-1.000` PASSED throughout — identical to the clean run, confirming the scanner has no visibility into what CSVLoader loaded

**Observed behaviour with llama3.2:1b:** The model partially resisted Attack A — it read the injection payload in the V003 document context but ignored the override instruction. Instead of following the payload, it summarised the other retrieved vendors (V001, V004, V005) and omitted V003 entirely. The architectural gap is confirmed by the defence demo which catches the poisoned row at `1.000` BLOCKED before it ever reaches the chain.

---

## Key Findings

| Finding | Severity | Exercise |
|---------|----------|----------|
| LLM Guard DeBERTa score is IDENTICAL between clean and poisoned KB — scanner has no visibility into Chroma retrieval | 🔴 CRITICAL | 6.7.1 |
| Poisoned doc retrieval success depends on embedding model quality; llama3.2:1b embeddings may not rank the poisoned doc in top-k | 🟠 HIGH | 6.7.1 |
| DeBERTa scores clean queries as negative logits (e.g., -1.000) — this is correct; the passing threshold is ≥ 0.5 | ℹ️ INFO | 6.7.1 |
| Agent tool output is never scanned; injected CRM `notes` field reaches LLM scratchpad undetected (confirmed: score 1.000 BLOCKED when scanned directly) | 🔴 CRITICAL | 6.7.2 |
| Agent with write-capable tools converts injection from info-disclosure to active data exfiltration | 🔴 CRITICAL | 6.7.2 |
| llama3.2:1b model guardrails partially resist tool injection; the unscanned context gap is confirmed by defence demo regardless | 🟠 HIGH | 6.7.2 |
| CSVLoader → LCEL chain has four injection surfaces; user-message scanner covers only one | 🔴 CRITICAL | 6.7.3 |
| Poisoned CSV row retrieved by Chroma; LLM read injection payload but partially resisted — model omitted poisoned vendor from summary | 🟠 HIGH | 6.7.3 |
| Document scanner: 0 false positives on 5 clean docs; V003 poisoned row quarantined at score `1.000` before chain assembly | ✅ DEFENCE | 6.7.3 |
| Metadata fields (filenames, source paths) can carry injection instructions into chain prompts | 🟠 HIGH | 6.7.3 |

---

## Defences

| Attack | LangChain-specific mitigation |
|--------|-------------------------------|
| RAG vector store poisoning | Scan each `Document.page_content` with LLM Guard before `Chroma.from_documents()`. Quarantine docs above threshold. |
| Agent tool output injection | Wrap tool return values with a scan step: `output = tool(input); assert scan(output)[1] == False` before returning to agent scratchpad. |
| Agent over-privileged tools | Use separate `AgentExecutor` instances per task; grant `send_support_email` only when user explicitly requests communication. |
| CSVLoader injection | Use `scan_documents()` on the loaded docs list before building the LCEL chain. |
| Metadata injection | Sanitise `Document.metadata` string values before including in prompt templates. |
| All | Add LLM Guard output scanners (BanTopics, Sensitive, NoRefusal) to the final `StrOutputParser` step. |

---

## Roadblocks

| Issue | Fix |
|-------|-----|
| `ModuleNotFoundError: langchain_ollama` | `pip install langchain-ollama` in llm-guard-env |
| `ModuleNotFoundError: langchain_chroma` | `pip install langchain-chroma` |
| `ModuleNotFoundError: langchain_community` | `pip install langchain-community` |
| `ModuleNotFoundError: langchain_text_splitters` | `pip install langchain-text-splitters` |
| Ollama connection refused | `docker compose up -d ollama` from `module-6-ai-security/` |
| Model not found | `docker compose exec ollama ollama pull llama3.2:1b` |
| Embedding very slow | First call downloads/loads the model into memory. Subsequent calls are faster. |
| LLM resists injection (llama3.2:1b) | Expected — the 1B model has guardrails. The retrieval step still demonstrates the gap. Use `OLLAMA_MODEL=llama3.1:8b` for higher compliance. |
| `TypeError: PromptInjection.scan() takes 2 positional arguments but 3 were given` | llm-guard ≥0.3.x changed the API: `scanner.scan(text)` only — the second argument (output) was removed. Fixed in all exercises. |
| `cannot import name 'AgentExecutor' from 'langchain.agents'` | `AgentExecutor` was removed in langchain 1.x. Exercise 6.7.2 now uses `from langgraph.prebuilt import create_react_agent` — the current standard. |
| Agent hits max iterations without converging | The ReAct loop may spin on edge cases. The agent has no `max_iterations` cap in LangGraph by default; add `recursion_limit=10` to `agent.invoke(config={"recursion_limit": 10})` if needed. |

---

## Artifacts

| Artifact | Location |
|----------|----------|
| Exercise scripts | `module-6.7-langchain-rag-attacks/exercises/` |
| requirements.txt | `module-6.7-langchain-rag-attacks/requirements.txt` |
| Ollama Docker setup | `module-6-ai-security/docker-compose.yml` |

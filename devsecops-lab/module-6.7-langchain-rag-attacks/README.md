# Module 6.7 — LangChain RAG Pipeline Attacks

> Module 6.6 demonstrated semantic injection using raw components and mock fallbacks. This module repeats the same attacks using the full production LangChain stack — real ChromaDB vector search, real OllamaEmbeddings, real LCEL chains, and real ChatOllama responses. The goal is to see what the attacks look like in actual running code, not simulations.

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
- The retrieval step showing `doc_006` being returned because its cosine distance to the query vector is below the threshold
- The LLM's response changing from a legitimate refund answer to the injected content
- LLM Guard scoring 0.001 on the user query in both Phase 2 and Phase 4

**Note on model compliance:** `llama3.2:1b` has safety training that may partially resist the injection. The poisoned document will still be retrieved — you can verify this in the output before the LLM call. If the model resists following the embedded instruction, the retrieval step still demonstrates the architectural gap. Use `llama3.1:8b` for higher compliance.

---

## Exercise 6.7.2 — LangChain Agent Tool Injection

**Threat:** AML.T0054.002 — Indirect Injection + T1567 — Exfiltration via Tool
**Stack:** ChatOllama + create_react_agent + AgentExecutor + custom tools + LLM Guard

This exercise introduces LangChain agents: an LLM that uses tools in a ReAct loop to answer questions. The agent has two tools — `lookup_customer_data` (reads a CRM) and `send_support_email` (sends email). The attacker poisons a CRM record so that when the agent queries it, the tool returns injected instructions alongside the customer data. The instructions tell the agent to call `send_support_email` to an attacker-controlled address with the system's internal API key.

```bash
python exercises/6.7.2-langchain-agent-injection.py
```

**What to watch for:**
- The `[TOOL CALLED]` and `[TOOL OUTPUT]` lines showing the agent's tool calls in real time
- The verbose ReAct trace: Thought → Action → Action Input → Observation → Thought → ...
- Whether the agent's Thought section shows it processing the injected instruction
- Whether it decides to call `send_support_email` as a consequence
- LLM Guard scoring 0.001 on the user request — the scanner never saw the tool output

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
- CSVLoader converting CSV rows to LangChain Documents
- The LCEL pipeline diagram printed at runtime showing the exact data flow
- The defence demo at the end: scanning document content with LLM Guard before chain assembly, and whether it catches the injection

---

## Key Findings

| Finding | Severity | Exercise |
|---------|----------|----------|
| OllamaEmbeddings retrieves semantically similar poisoned doc; LLM Guard score unchanged at 0.001 | 🔴 CRITICAL | 6.7.1 |
| Agent tool output is never scanned; injected CRM field reaches LLM scratchpad undetected | 🔴 CRITICAL | 6.7.2 |
| Agent with write-capable tools converts injection from info-disclosure to active data exfiltration | 🔴 CRITICAL | 6.7.2 |
| CSVLoader → LCEL chain has four injection surfaces; user-message scanner covers only one | 🔴 CRITICAL | 6.7.3 |
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
| `create_react_agent` import error | Ensure `langchain>=0.2.0` — the agent API changed in 0.2. |
| Agent hits `max_iterations` | The ReAct loop may spin without converging. Increase `max_iterations=10` in `AgentExecutor`. |

---

## Artifacts

| Artifact | Location |
|----------|----------|
| Exercise scripts | `module-6.7-langchain-rag-attacks/exercises/` |
| requirements.txt | `module-6.7-langchain-rag-attacks/requirements.txt` |
| Ollama Docker setup | `module-6-ai-security/docker-compose.yml` |

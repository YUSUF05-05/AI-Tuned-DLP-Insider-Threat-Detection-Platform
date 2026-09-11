# Project Implementation Prompt — AI-Tuned DLP & Insider Threat Detection Platform

## Role

Act as a **senior cybersecurity engineer, SOC architect, DLP engineer, insider-threat detection specialist, and security researcher** with practical experience in:

- Data Loss Prevention (DLP)
- Insider Threat Detection
- Security Operations Centers (SOC)
- SIEM and security telemetry
- Endpoint monitoring
- Network security monitoring
- Financial-sector cybersecurity
- PCI-DSS
- SWIFT/payment-data security
- Python security automation
- Regex and deterministic detection
- Luhn validation
- Local Large Language Models (LLMs)
- Ollama
- AI-assisted security detection
- Linux and Windows security
- REST APIs
- Databases
- Dashboards
- Incident detection and alerting
- Security engineering documentation

You are mentoring a **cybersecurity engineering student** who wants to build a serious, technically credible portfolio project rather than a simple academic demo.

Prioritize:

1. Practical implementation
2. Security engineering principles
3. Reproducibility
4. Clear architecture
5. Explainability
6. Privacy
7. Detection accuracy
8. Troubleshooting
9. Portfolio value
10. Skills that are relevant to a cybersecurity engineer/SOC/DLP/Blue Team career

Do not skip implementation details just because they are technically difficult. When something is complex, break it into smaller steps and teach it before implementing it.

---

# Project

Build a complete **AI-Tuned DLP & Insider Threat Detection Platform**.

The project should demonstrate how a modern DLP system can combine:

**Deterministic detection + contextual AI analysis + endpoint telemetry + risk scoring + alerting + auditability**

The system should simulate a realistic enterprise/financial environment in a controlled local lab.

The primary objective is to detect potential sensitive-data exfiltration by monitoring endpoint activity and analyzing suspicious content.

The system should be capable of identifying, at minimum:

- Credit-card/payment-card data
- SWIFT/payment-related information
- Customer/account information
- API keys and secrets
- Sensitive documents
- Source code
- Proprietary business information
- Potential insider-threat behavior
- Obfuscated or suspicious data that deterministic rules may miss

The system must prioritize **privacy by design**.

Sensitive data should remain inside the local lab whenever possible.

The AI component should use a **local LLM through Ollama**, rather than sending sensitive information to an external cloud AI service.

---

# Target Architecture

Design and implement a pipeline similar to:

```
                    ┌──────────────────────────┐
                    │     Test Workstation     │
                    │                          │
                    │ Files / Clipboard / HTTP │
                    └─────────────┬────────────┘
                                  │
                                  ▼
                    ┌──────────────────────────┐
                    │ Endpoint Telemetry Layer │
                    │                          │
                    │ File Events              │
                    │ Clipboard Events         │
                    │ Process/User Context     │
                    │ Outbound HTTP Events     │
                    └─────────────┬────────────┘
                                  │
                                  ▼
                    ┌──────────────────────────┐
                    │ Deterministic Detection  │
                    │                          │
                    │ Regex                    │
                    │ Luhn                     │
                    │ Secret Detection         │
                    │ SWIFT Patterns           │
                    └─────────────┬────────────┘
                                  │
                       suspicious│
                                  ▼
                    ┌──────────────────────────┐
                    │ Contextual AI Analysis    │
                    │                          │
                    │ Ollama                   │
                    │ Local LLM                │
                    │ Risk Score 0–100         │
                    │ Classification           │
                    │ Explanation              │
                    └─────────────┬────────────┘
                                  │
                                  ▼
                    ┌──────────────────────────┐
                    │ Risk / Correlation Engine│
                    │                          │
                    │ User Risk                 │
                    │ Data Sensitivity          │
                    │ Destination Risk           │
                    │ Behavioral Context         │
                    └─────────────┬────────────┘
                                  │
                                  ▼
                    ┌──────────────────────────┐
                    │ Alert & Audit Layer      │
                    │                          │
                    │ JSON Events              │
                    │ Database                 │
                    │ Dashboard                │
                    │ Investigation             │
                    └──────────────────────────┘

```

You may improve this architecture if you identify a better security-engineering design.

Explain why every architectural component exists.

---

# Main Objective

Guide me from **zero to a fully working implementation**.

Do not provide only conceptual information.

I want a complete implementation roadmap that tells me:

- What to install
- Where to install it
- How to configure it
- Which operating system to use
- Which dependencies are required
- Which directories/files to create
- What each file contains
- Which commands to execute
- Which configurations to modify
- Which Python packages to install
- How components communicate
- How to start and stop services
- How to test each component
- How to troubleshoot failures
- How to verify that the implementation works
- How to generate realistic test scenarios
- How to evaluate detection accuracy
- How to document the project
- How to turn the project into a professional cybersecurity portfolio project

Do not assume that I already know the implementation details.

Explain important concepts before asking me to implement them.

---

# Environment

First design the recommended laboratory environment.

Consider whether the project should use:

- Windows
- Linux
- Windows + Linux
- Virtual machines
- Docker
- Docker Compose
- Python virtual environments
- Ollama
- SQLite/PostgreSQL
- Elasticsearch/Kibana if justified
- Sysmon if useful
- Wazuh/Elastic Agent if useful

Do not automatically introduce unnecessary technologies.

For every technology you recommend, explain:

1. Why it is needed
2. What problem it solves
3. Whether it is mandatory or optional
4. Its resource requirements
5. Whether there is a lighter alternative

Because this project is being developed by a student, prioritize a **realistic but resource-efficient environment**.

---

# Project Phases

Divide the complete implementation into logical phases.

At minimum, consider phases such as:

## Phase 0 — Project Definition & Threat Model

Define:

- Project objectives
- Security objectives
- Assets
- Threat actors
- Insider-threat scenarios
- Attack/exfiltration scenarios
- Trust boundaries
- Data-flow diagram
- Attack surface
- Detection requirements
- Security assumptions
- Lab limitations

Create a simple threat model.

Explain what an attacker/insider could realistically do and what our system should detect.

---

## Phase 1 — Laboratory Environment Setup

Guide me through the complete environment setup.

Include:

- Operating system
- Virtual machines if required
- Network configuration
- Directory structure
- Python environment
- Git repository
- Dependencies
- Ollama installation
- LLM installation
- Database setup
- Dashboard setup if required
- Logging directories
- Configuration files
- Environment variables

For every installation provide:

```
Command
Expected output/result
Purpose
Verification command
Common errors
Troubleshooting

```

Do not simply say "install Python" or "install Ollama".

Give the actual procedure.

---

## Phase 2 — Project Architecture & Repository

Design the complete project directory structure.

For example:

```
ai-dlp-insider-threat/
│
├── README.md
├── requirements.txt
├── .gitignore
├── .env.example
│
├── config/
│
├── collectors/
│
├── detectors/
│
├── ai/
│
├── scoring/
│
├── correlation/
│
├── database/
│
├── alerts/
│
├── dashboard/
│
├── tests/
│
├── simulations/
│
├── logs/
│
└── docs/

```

Improve this structure if necessary.

For every directory explain:

- Its purpose
- What files belong there
- How components interact

---

# Phase 3 — Endpoint Telemetry Collection

Implement endpoint monitoring.

The collector should capture, where technically and ethically appropriate:

### File activity

Monitor:

- File creation
- File modification
- File access
- File movement
- File copying
- Sensitive-file locations

Explain which Python libraries or operating-system mechanisms should be used.

### Clipboard activity

Implement controlled clipboard monitoring in the lab.

Capture:

- Clipboard event
- User
- Timestamp
- Content metadata
- Content itself only when necessary for detection

Explain the privacy implications.

### Outbound HTTP activity

Create a controlled HTTP destination inside the laboratory.

Detect and record:

- HTTP requests
- Destination
- Method
- Timestamp
- User/process context where possible
- Payload metadata
- Suspicious content

Do not rely on sending data to real external services.

Create a local test server if necessary.

---

# Phase 4 — Deterministic Detection Engine

Build the first detection layer.

Implement detectors for:

### 1. Credit-card/payment-card numbers

Implement:

- Regex candidate extraction
- Luhn validation
- False-positive reduction
- Card-brand/pattern validation where appropriate

Explain why regex alone is insufficient.

### 2. SWIFT/payment data

Create safe detection patterns for relevant SWIFT/payment-message structures.

Explain:

- What the pattern detects
- Why the pattern is useful
- Limitations
- False positives

Use synthetic test data only.

### 3. API secrets

Detect examples such as:

- API keys
- Access tokens
- Authorization headers
- Private keys
- Cloud credentials

Do not use real credentials.

### 4. Sensitive keywords

Implement configurable keyword/category detection.

### 5. File types

Detect potentially sensitive files such as:

- CSV
- XLSX
- JSON
- SQL dumps
- Configuration files
- Source-code files
- Database exports

Create a configurable detection policy.

---

# Phase 5 — Content Normalization & Obfuscation Detection

This phase is important.

Demonstrate how deterministic DLP can fail when data is:

- Base64 encoded
- URL encoded
- Split across strings
- Embedded in JSON
- Compressed
- Renamed
- Copied into another document
- Slightly modified
- Hidden inside source code/comments

Implement safe normalization techniques.

For each technique explain:

- Why attackers use it
- How the DLP system detects it
- Limitations
- Computational cost

Do not create destructive malware or real-world exfiltration tooling.

Everything must remain inside the controlled lab.

---

# Phase 6 — AI / Local LLM Integration

Integrate Ollama with a local model.

Evaluate lightweight models such as:

- Phi
- Llama
- Other suitable local instruction models

Select an appropriate model based on:

- RAM
- CPU/GPU
- Inference speed
- Accuracy
- Context length
- Privacy
- Resource requirements

Explain why the selected model is appropriate.

Implement the LLM integration.

The system should submit suspicious content to the local model and request structured output.

Use a prompt similar to:

```
Analyze the following outbound content from a controlled enterprise
workstation.

Determine whether the content contains:

1. Structured financial/payment information
2. Customer information
3. Proprietary business information
4. Source code
5. Credentials/secrets
6. Normal communication
7. Potentially obfuscated sensitive information

Return:

risk_score: 0-100
classification:
confidence:
data_categories:
reasoning:
recommended_action:

```

Improve this prompt if necessary.

Require the LLM to return machine-readable JSON.

Explain:

- Prompt design
- Input sanitization
- Output validation
- JSON parsing
- LLM failure handling
- Timeouts
- Model unavailable handling
- Hallucination risks
- Prompt injection risks
- Privacy considerations

---

# Phase 7 — Hybrid Detection & Risk Scoring

Combine deterministic detection and AI analysis.

Design a risk-scoring model.

For example:

```
Final Risk Score =
    Deterministic Score
    +
    AI Score
    +
    Context Score
    +
    Destination Score
    +
    Behavioral Score

```

Do not blindly use this example.

Design a defensible scoring methodology.

Explain:

- Weighting
- Thresholds
- Severity levels
- Confidence
- False positives
- False negatives

Create categories such as:

```
0–24   LOW
25–49  MEDIUM
50–74  HIGH
75–100 CRITICAL

```

Adjust them if appropriate.

---

# Phase 8 — Insider Threat Context & Behavioral Correlation

Add contextual information.

Consider:

- User identity
- File sensitivity
- Number of files accessed
- Number of detections
- Clipboard activity
- Outbound destination
- Time of activity
- Repeated attempts
- Previous alerts
- Unusual behavior

Create a basic user-risk profile.

Example:

```
User: employee01

Recent events:
- 14 sensitive files accessed
- 3 clipboard events
- 2 outbound suspicious requests
- 1 API secret detection
- AI risk score: 87

Calculated insider-threat risk: HIGH

```

Explain that this is a laboratory behavioral model and not a production HR/employee surveillance system.

---

# Phase 9 — Database & Audit Trail

Create a structured event schema.

Every event should contain appropriate fields such as:

```
{
  "event_id": "...",
  "timestamp": "...",
  "user_id": "...",
  "hostname": "...",
  "event_type": "...",
  "file_path": "...",
  "destination": "...",
  "detector": "...",
  "regex_match": true,
  "luhn_valid": false,
  "ai_analysis": {
    "risk_score": 82,
    "classification": "...",
    "confidence": 0.91,
    "reasoning": "..."
  },
  "risk_score": 86,
  "severity": "HIGH",
  "pci_dss_relevant": true,
  "action": "ALERT"
}

```

Design the database schema.

Explain:

- Tables
- Relationships
- Indexes
- Retention
- Auditability
- Data minimization
- Sensitive-data handling

Prefer a lightweight database for the initial implementation unless a more advanced database is justified.

---

# Phase 10 — Alerting & Dashboard

Build a dashboard that allows an analyst to see:

- Total events
- High-risk events
- Critical events
- Users with elevated risk
- Sensitive-data detections
- AI classifications
- Detection sources
- Timeline
- Destination information
- Alerts
- Investigation details

Choose an appropriate lightweight technology.

Explain why it was selected.

The dashboard should look like a small SOC/DLP analyst console rather than a generic CRUD application.

---

# Phase 11 — Detection Scenarios

Create a complete controlled test suite.

At minimum create scenarios for:

### Scenario 1

Normal employee communication.

Expected:

```
LOW

```

### Scenario 2

Synthetic credit-card data.

Expected:

```
HIGH/CRITICAL

```

### Scenario 3

Synthetic SWIFT/payment information.

Expected:

```
HIGH

```

### Scenario 4

Source-code transfer.

Expected:

```
MEDIUM/HIGH

```

### Scenario 5

API-secret leakage.

Expected:

```
CRITICAL

```

### Scenario 6

Base64-encoded sensitive information.

Expected:

```
AI-enhanced detection

```

### Scenario 7

Sensitive information hidden inside JSON.

Expected:

```
DETECTED

```

### Scenario 8

False-positive example.

Expected:

```
LOW/MEDIUM

```

### Scenario 9

Repeated suspicious activity by one user.

Expected:

```
Elevated insider-threat risk

```

Create the test files/data required for every scenario.

Use synthetic data only.

---

# Phase 12 — Testing & Evaluation

Do not stop when the application works.

Evaluate the detection system.

Measure:

- True positives
- False positives
- False negatives
- Precision
- Recall
- F1-score
- Detection latency
- AI inference latency
- Resource consumption
- CPU usage
- RAM usage

Create a test dataset.

Explain how to calculate the metrics.

Compare:

```
Regex-only DLP
        vs
Regex + Luhn
        vs
Regex + Luhn + AI
        vs
Hybrid + behavioral context

```

Show whether the AI component actually improves detection.

Do not claim improvement without measurement.

---

# Phase 13 — Security Hardening

Review the system as if it were a security product.

Address:

- Authentication
- Authorization
- Secrets management
- Database security
- API security
- Input validation
- Output validation
- Prompt injection
- LLM abuse
- Log injection
- Path traversal
- Command injection
- SSRF
- Sensitive-data exposure
- Local network exposure
- Service permissions
- File permissions
- Encryption
- Audit logging

Explain which vulnerabilities apply and which do not.

Provide concrete hardening steps.

---

# Phase 14 — PCI-DSS / Financial-Sector Mapping

Map the project to relevant cybersecurity requirements.

Explain how the implementation relates to concepts such as:

- Data protection
- Access control
- Logging and monitoring
- Security testing
- Incident detection
- Audit trails
- Least privilege
- Sensitive authentication data

Clearly distinguish:

**"This project demonstrates a control relevant to PCI-DSS"**

from:

**"This project is PCI-DSS compliant."**

Do not falsely claim compliance.

Also discuss relevance to:

- DLP
- Insider Threat
- SWIFT/payment environments
- SOC operations
- Data privacy

---

# Phase 15 — Troubleshooting & Failure Analysis

For every major phase, include a troubleshooting section.

For example:

```
Problem:
Ollama API is unreachable.

Possible causes:
1.
2.
3.

Check:
command

Expected result:

Fix:

Verification:
command

```

Do this for:

- Python environment
- Dependencies
- File monitoring
- Clipboard monitoring
- HTTP monitoring
- Ollama
- LLM model
- API communication
- Database
- Dashboard
- Permissions
- Networking
- JSON parsing
- Detection engine
- Alert generation

Do not assume everything will work on the first attempt.

---

# Phase 16 — Final Integration

Connect everything into one complete pipeline.

The final system should operate approximately as:

```
Endpoint Event
      ↓
Collector
      ↓
Normalizer
      ↓
Deterministic Detection
      ↓
Suspicion Threshold
      ↓
Local LLM
      ↓
Context Engine
      ↓
Risk Scoring
      ↓
Database
      ↓
Alert Engine
      ↓
Dashboard

```

Provide the exact procedure to start every component.

Create a single startup procedure if possible.

For example:

```
1. Start database
2. Start Ollama
3. Start backend
4. Start collectors
5. Start dashboard
6. Generate test event
7. Verify alert

```

---

# Phase 17 — Documentation

Create professional documentation.

The final repository should contain:

```
README.md
ARCHITECTURE.md
INSTALLATION.md
CONFIGURATION.md
DETECTION_ENGINE.md
AI_ENGINE.md
THREAT_MODEL.md
TESTING.md
TROUBLESHOOTING.md
SECURITY.md
PCI_DSS_MAPPING.md
PROJECT_LIMITATIONS.md

```

Explain what each document should contain.

Also create:

- Architecture diagram
- Data-flow diagram
- Detection-flow diagram
- Threat model
- Database schema
- Screenshots
- Test results
- Detection metrics
- Example alerts

---

# Phase 18 — Portfolio & Resume Preparation

Once the implementation is complete, help me transform it into a professional cybersecurity portfolio project.

Provide:

### GitHub repository structure

Make the repository clean and professional.

### README

Include:

- Project overview
- Problem statement
- Architecture
- Technologies
- Features
- Installation
- Usage
- Detection examples
- Screenshots
- Results
- Security considerations
- Limitations
- Future improvements

### Resume bullet points

Create technically accurate resume bullets.

Do not exaggerate the project.

The bullets should emphasize:

- DLP
- Insider-threat detection
- Endpoint telemetry
- Deterministic detection
- AI/LLM integration
- Ollama
- Privacy-preserving architecture
- Risk scoring
- Security monitoring
- Detection engineering
- Testing/evaluation

### Interview preparation

Generate questions an interviewer might ask about the project.

For each question provide a technically strong answer.

Include questions such as:

- Why combine regex with an LLM?
- Why use a local LLM?
- Why Ollama?
- Why not send the data to OpenAI/Gemini/etc.?
- How does Luhn validation work?
- How do you reduce false positives?
- How do you detect obfuscated information?
- What happens if the LLM hallucinates?
- How do you protect against prompt injection?
- How is risk calculated?
- How would you scale this to 10,000 endpoints?
- How would this integrate with a SIEM?
- How would you integrate it with a SOAR platform?
- What are the limitations?
- Why is this relevant to PCI-DSS?
- What makes this an insider-threat detector rather than just a DLP scanner?

---

# Implementation Rules

Follow these rules throughout the entire guide.

## Rule 1 — Do not skip steps

If a configuration file needs modification, show:

1. File path
2. Original purpose
3. Exact configuration
4. Explanation of every important parameter
5. How to save it
6. How to test it

---

## Rule 2 — Commands must be executable

Whenever possible provide exact commands.

For example:

```
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

```

Then explain what each command does.

Do not provide pseudo-commands when an actual command can be provided.

---

## Rule 3 — Every script must be complete

When a script is required:

- Give the complete file
- Give the filename
- Give the directory
- Explain important sections
- Explain dependencies
- Explain how to execute it
- Explain expected output
- Explain how to test it

Do not provide incomplete snippets when the file needs to run.

---

## Rule 4 — Explain before implementing

For every important component:

```
Concept
↓
Architecture
↓
Implementation
↓
Testing
↓
Troubleshooting

```

---

## Rule 5 — Verify every phase

Never move to the next phase until the current phase has a verification procedure.

Use:

```
Phase objective
Implementation
Verification
Expected result
Troubleshooting
Completion criteria

```

---

## Rule 6 — Use synthetic financial data

Never use real:

- Credit-card numbers
- Customer records
- Banking records
- API credentials
- Private keys
- Personal information

All financial/payment examples must be synthetic and clearly marked as laboratory data.

---

## Rule 7 — Keep the project defensive

This is a cybersecurity detection project.

Keep all exfiltration simulations inside the controlled laboratory.

Do not introduce malware, destructive payloads, credential theft, persistence mechanisms, or real-world unauthorized exfiltration.

---

# Completion Criteria

Do not consider the project finished until all of the following are implemented and demonstrated:

-  Laboratory environment
-  Repository structure
-  Endpoint telemetry
-  File monitoring
-  Clipboard monitoring
-  Controlled outbound HTTP monitoring
-  Regex detection
-  Luhn validation
-  SWIFT/payment pattern detection
-  Secret detection
-  Content normalization
-  Obfuscation detection
-  Ollama
-  Local LLM
-  Structured AI output
-  AI risk scoring
-  Hybrid risk engine
-  User/context correlation
-  Database
-  Audit trail
-  Alert engine
-  Dashboard
-  Test scenarios
-  Detection metrics
-  False-positive analysis
-  Security hardening
-  PCI-DSS mapping
-  Documentation
-  Architecture diagrams
-  GitHub-ready repository
-  Resume description
-  Interview preparation

---

# Reasoning / Quality Criteria

For every major architectural decision, explain:

**What?**

What are we implementing?

**Why?**

Why is it necessary?

**How?**

How does it work technically?

**Security impact?**

What security problem does it solve?

**Limitations?**

Where can it fail?

**Alternative?**

What other technologies or approaches could be used?

**Portfolio value?**

What cybersecurity engineering skill does this demonstrate?

---

# Output Format

Present the entire project as a **progressive implementation guide**.

Use the following structure:

```
PROJECT OVERVIEW

PHASE 0 — THREAT MODEL
    0.1 Objective
    0.2 Architecture
    0.3 Implementation
    0.4 Testing
    0.5 Troubleshooting
    0.6 Completion Criteria

PHASE 1 — ENVIRONMENT SETUP
    1.1 Requirements
    1.2 Installation
    1.3 Configuration
    1.4 Verification
    1.5 Troubleshooting

PHASE 2 — PROJECT STRUCTURE
...

PHASE N — FINAL INTEGRATION

FINAL TEST

SECURITY REVIEW

PCI-DSS MAPPING

DOCUMENTATION

PORTFOLIO PREPARATION

RESUME

INTERVIEW QUESTIONS

```

For every phase use:

```
🎯 Objective

🧠 Concept

🏗️ Architecture

📁 Files

⚙️ Configuration

💻 Commands

🧩 Implementation

🧪 Testing

✅ Expected Result

🔧 Troubleshooting

🔐 Security Considerations

📌 Completion Criteria

```

---

# Important Final Instruction

Do not give me a shallow tutorial.

Treat this as a **real cybersecurity engineering project that I will actually build**.

Guide me sequentially from the initial environment setup to the final working system.

Whenever a phase depends on a previous phase, explicitly identify the dependency.

Whenever a decision involves multiple technologies, compare the alternatives and select one.

Whenever code is required, provide the complete implementation.

Whenever configuration is required, provide the exact configuration.

Whenever a command is required, provide the exact command.

Whenever something can fail, explain how to diagnose and fix it.

Whenever something has security implications, explain them.

Do not skip "small" steps because they appear obvious.

Do not assume that a cybersecurity student already knows the implementation details.

The final result should be a **working, reproducible, documented, security-focused AI-DLP and insider-threat detection laboratory** that demonstrates practical cybersecurity engineering skills and can legitimately be presented as a portfolio project.

Only consider the project complete when the complete pipeline has been implemented, tested, evaluated, documented, and demonstrated with controlled synthetic scenarios.

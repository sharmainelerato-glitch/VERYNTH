# ✦ VERYNTH

### Intelligence, connected.

**An AI-powered workspace for investigation, research, engineering, verification, and human–AI collaboration.**

[Live Website](https://13-244-118-60.sslip.io/) | [GitHub Repository](https://github.com/sharmainelerato-glitch/VERYNTH)

---

## Overview

VERYNTH is a connected intelligence platform designed to help people investigate complex information, connect evidence, collaborate, and make better-informed decisions.

At its centre is **Ness**, an AI assistant designed to support contextual reasoning, evidence analysis, research, and multidisciplinary problem-solving.

VERYNTH explores a future where AI does more than answer isolated questions. It helps people investigate, build, verify, and collaborate within a connected environment.

**Our vision:** Make advanced intelligence accessible, collaborative, explainable, and useful across disciplines.

## The Problem

Modern knowledge work is fragmented across documents, AI assistants, development environments, research tools, and communication platforms.

This makes it difficult to:

- Maintain context across investigations.
- Connect information from different sources.
- Identify contradictions and unsupported conclusions.
- Collaborate on complex technical problems.
- Review and verify AI-generated recommendations.
- Preserve evidence, decisions, and project history.

VERYNTH aims to bring these activities into one environment.

## Key Capabilities

### 1. Ness — AI Intelligence Partner

Ness is the contextual AI assistant within VERYNTH.

The platform is designed to support questions, evidence-grounded investigations, research, and cross-disciplinary workflows.

### 2. Evidence Intelligence

VERYNTH includes workflows for examining source material, comparing information, identifying relationships, and investigating potential contradictions.

### 3. Projects and Library

A persistent workspace for organizing investigations, project materials, uploaded files, and related work.

### 4. Human–AI Collaboration

VERYNTH includes collaboration components designed to support shared investigations, team discussions, human review, and coordinated work.

### 5. Engineering Intelligence

The codebase includes engineering-oriented tools for examining technical changes, software evidence, verification results, and proposed improvements.

### 6. Cross-Disciplinary Intelligence

VERYNTH is designed to explore applications across:

- Software engineering and cybersecurity
- Science and research
- Finance and data analysis
- Robotics and technical systems
- Education and multidisciplinary knowledge work

### 7. Verification and Human Oversight

VERYNTH emphasizes reviewing evidence, identifying uncertainty, and distinguishing AI-generated suggestions from independently verified outcomes.

## Technology Stack

| Layer | Technology |
|---|---|
| Backend | Python, FastAPI |
| Frontend | HTML, CSS, JavaScript |
| AI | Configurable AI model integrations |
| Authentication | AWS Cognito and protected owner access |
| Hosting | Amazon EC2 |
| Reverse Proxy | Nginx |
| HTTPS | TLS-enabled deployment |
| Data and Storage | Application persistence and AWS integrations |
| Background Processing | Python worker components |

## Architecture

```text
                  VERYNTH
                     |
                HTTPS / Nginx
                     |
                   FastAPI
                     |
        +------------+------------+
        |            |            |
     Frontend    Authentication  API Layer
        |            |            |
     Ness AI       Cognito     Investigations
     Workspace     Owner       Collaboration
        |          Access      Engineering
        |                         |
        +------------+------------+
                     |
              Data and Storage
                     |
             Background Workers
```

## Live Deployment

**Website:** https://13-244-118-60.sslip.io/

VERYNTH is deployed on Amazon EC2 using FastAPI and Nginx.

Visitors can access the public landing page and authentication experience.

The private owner workspace is separately protected.

**Current limitation:** Although AWS Cognito authentication is implemented, complete independent user workspace provisioning and data isolation are not yet available for general public accounts. The full product demonstration currently uses protected owner access.

## Running Locally

### Requirements

- Python 3.12+
- uv
- Required environment variables for configured integrations

### 1. Clone the repository

```bash
git clone https://github.com/sharmainelerato-glitch/VERYNTH.git
cd VERYNTH
```

### 2. Create a Python environment

```bash
uv venv
```

### 3. Install dependencies

```bash
uv pip install -r requirements.txt
```

### 4. Configure the environment

Set the required environment variables for your selected AI providers, authentication services, and storage integrations.

Never commit API keys, passwords, tokens, or private credentials.

### 5. Start the application

```bash
uv run uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000 in your browser.

Some capabilities require additional external services and cloud configuration.

## Responsible AI and Security

VERYNTH is developed around these principles:

- Human oversight of consequential decisions.
- Evidence-grounded reasoning.
- Transparency about uncertainty and limitations.
- Authentication and access controls.
- Protection of credentials and private information.
- Separation of public experiences from private workspaces.
- Clear distinction between proposed and verified outcomes.

A file hash can establish file identity, but it cannot prove that its contents are true.

**Security status:** VERYNTH remains an actively developed prototype and has not undergone a comprehensive production security audit.

## Current Development Status

The repository contains the FastAPI application, frontend interfaces, authentication components, investigation workflows, AI integrations, collaboration modules, and background worker infrastructure.

Some advanced capabilities are experimental, partially implemented, or dependent on external services.

### Planned Improvements

- Complete multi-user workspace isolation.
- Expanded multimodal intelligence.
- More comprehensive evidence verification.
- Stronger collaborative workflows.
- Expanded engineering and scientific intelligence.
- Further security testing and reliability improvements.

## Why VERYNTH?

Most AI tools focus on producing answers.

VERYNTH explores a broader question:

**What if AI could help people investigate, build, collaborate, question conclusions, and maintain context within the same environment?**

The goal is not simply to generate answers, but to support the process of reaching better-informed conclusions.

---

## Creator

**Lerato Mokgatla**

Software Development | Cybersecurity | AI Engineering

[GitHub](https://github.com/sharmainelerato-glitch) | [Portfolio](https://leratosportfolio.vercel.app/)

---

**✦ VERYNTH — Intelligence, connected.**

*Built to explore a more connected future for human and artificial intelligence.*

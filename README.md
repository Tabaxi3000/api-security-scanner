```ruby
███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗
██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
```

[![Python](https://img.shields.io/badge/Python-3.13+-3776AB?style=flat&logo=python&logoColor=white)](https://www.python.org)
[![React](https://img.shields.io/badge/React-18+-61DAFB?style=flat&logo=react&logoColor=black)](https://react.dev)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?style=flat&logo=docker)](https://www.docker.com)
[![OWASP](https://img.shields.io/badge/OWASP-API_Top_10-orange?style=flat)](https://owasp.org/API-Security/)

> Full-stack API vulnerability scanner targeting the OWASP API Security Top 10 with configurable scan modules and a React dashboard.

<p align="center">
  <a href="https://youtu.be/CvuvFfh24cE">
    <img src="https://img.shields.io/badge/Watch_on-YouTube-FF0000?logo=youtube&logoColor=white" alt="Watch on YouTube">
  </a>
</p>

<p align="center">
  <a href="https://youtu.be/CvuvFfh24cE">
    <img src="https://img.youtube.com/vi/CvuvFfh24cE/maxresdefault.jpg" alt="Video Thumbnail" width="800">
  </a>
</p>

## What It Does

- Scans REST APIs against OWASP API Security Top 10 vulnerability categories
- Tests for authentication bypass, injection flaws, IDOR, and rate limiting weaknesses
- SQLi, authentication, IDOR, and rate limit scanner modules with configurable payloads
- JWT auth with bcrypt password hashing and session management
- Scan history tracking with detailed vulnerability reports per endpoint
- Full React dashboard for configuring scans and reviewing results

## Quick Start

```bash
docker compose up -d
```

Visit `http://localhost:8080` to open the dashboard.

> [!TIP]
> This project uses [`just`](https://github.com/casey/just) as a command runner. Type `just` to see all available commands.
>
> Install: `curl -sSf https://just.systems/install.sh | bash -s -- --to ~/.local/bin`

## Stack

**Backend:** FastAPI, SQLAlchemy, PostgreSQL, Alembic, httpx, aiohttp

**Frontend:** React, TypeScript, Vite

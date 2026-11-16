<div align="center">

<!-- AS Monogram Logo (White on Void Black with Signal Red Accent) -->
<svg viewBox="0 0 120 60" width="110" xmlns="http://www.w3.org/2000/svg">
  <polygon points="4,56 34,4 64,56 50,56 34,28 18,56" fill="#FFFFFF"/>
  <path d="M70 12H116L108 26H90L87 31H112L103 56H58L66 42H92L95 37H68Z" fill="#FF2E3B"/>
</svg>

# 🎯 BUG BOUNTY BOOTCAMP
### `0x3bdo` // *THINK BEYOND THE SYSTEM.*

**A hands-on offensive security companion to Vickie Li's *Bug Bounty Bootcamp* — bridging extended Notion research, custom vibe-coded vulnerable labs, exploitation writeups, and automation tools.**

[![Author](https://img.shields.io/badge/Author-0x3bedo-000000?style=for-the-badge&logo=github&logoColor=white)](https://github.com/3bod999)
[![Notion Knowledge Base](https://img.shields.io/badge/Notion-Full_Book_Summary_&_Extra_Notes-FF2E3B?style=for-the-badge&logo=notion&logoColor=white)](https://versed-chinchilla-977.notion.site/Bug-Bounty-Bootcamp-405106bce7bf8055b3c3c55fe9cd6fb3?pvs=74)
[![Labs Status](https://img.shields.io/badge/Labs-Active_Build-000000?style=for-the-badge&logo=hackthebox&logoColor=FF2E3B)](#-labs--modules-roadmap)
[![License](https://img.shields.io/badge/License-MIT-8C8C8C?style=for-the-badge)](LICENSE)

[📖 **Read Full Notes on Notion**](https://versed-chinchilla-977.notion.site/Bug-Bounty-Bootcamp-405106bce7bf8055b3c3c55fe9cd6fb3?pvs=74) • [🧪 **Explore Labs**](#-labs--modules-roadmap) • [🛠️ **Tools & Scripts**](./tools) • [🚀 **Quick Start**](#-quick-start)

</div>

---

## 📌 Overview

Reading theory isn't enough—you have to break systems to understand how they fail. This repository transforms *Bug Bounty Bootcamp* into a practical, self-contained training ground:

* **📖 Extended Notion Knowledge Base:** Every chapter of the book summarized, structured, and expanded with additional hunting spots, filter bypasses, and chaining scenarios.
* **🧪 Custom Vulnerable Labs:** Intentionally vulnerable web applications built specifically to practice each vulnerability class locally in an isolated environment.
* **🚩 Step-by-Step Writeups (`WRITEUP.md`):** Detailed walkthroughs for every lab covering **Discovery**, **Exploitation**, and **Remediation**.
* **🛠️ Offensive Tools & Scripts:** Custom Python and Bash utilities written to automate recon, parameter discovery, and exploitation workflows.

---

## 🗂️ Repository Architecture

```text
bug-bounty-bootcamp-/
├── README.md                 # Main hub, Notion knowledge base link & roadmap
├── 01-Reconnaissance/        # Recon methodologies & automation scripts
├── 02-XSS/
│   ├── lab-app/              # Vulnerable web app source code
│   ├── README.md             # Challenge briefing & local setup
│   └── WRITEUP.md            # Exploitation walkthrough & patch guide
├── 03-IDOR/
│   ├── lab-app/
│   ├── README.md
│   └── WRITEUP.md
├── 04-SQL-Injection/
│   └── ...
└── tools/                    # Custom offensive scripts & helpers
    └── ...

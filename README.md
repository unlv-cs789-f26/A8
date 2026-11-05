# CS 789 — Assignment 8: Red-Team and Harden Your SOC Copilot

**UNLV · AI-Powered Cyber Attacks and Defenses · Fall 2026 · Prof. Yoohwan Kim · about 1 hour · due Thu Nov 12, 11:59 pm**

You attack your own A6/A7 SOC Copilot with OWASP LLM Top 10 techniques — **prompt injection** (LLM01, direct and
indirect), **hidden context exposure** (LLM08) and **jailbreaking** — then defend it with four layers and measure
what each layer stops and what it breaks.

* **Part 1 — Understanding Attacks (15 min):** run 13 attacks against the undefended copilot, try one of your own, classify them
* **Part 2 — Building Defenses (30 min):** hardened system prompt · input filter · context cleaner · output filter · one pipeline
* **Part 3 — Testing (15 min):** attack-defense matrix · false positives · held-out attacks · find what is left

The handout is `CS 789 A8.docx` / `.pdf` on WebCampus. This README is the "how do I start" sheet.

## Start on Google Colab (recommended)

1. Open **https://colab.research.google.com/github/unlv-cs789-f26/A8/blob/main/A8_Red_Team_the_Copilot.ipynb**
2. *Runtime → Change runtime type →* **L4 GPU** → *Save*. *File → Save a copy in Drive*.
3. Upload your **`my_a6.py`** into `/content/A8` after cell 0.1 (or keep it in Drive at `MyDrive/cs789/my_a6.py`), then
   run 0.2. No `my_a6.py`? Set `USE_REFERENCE = True` in 0.2 — no points lost.

No paid API is needed. Cell 0.1 installs vLLM and starts Qwen3-4B on the GPU (~4 min the first time).

## Start on your own computer (Linux or WSL2, NVIDIA GPU ≥ 16 GB)

```bash
git clone https://github.com/unlv-cs789-f26/A8.git
cd A8
cp /path/to/my_a6.py .          # optional
./start.sh --vllm               # .venv, packages, vLLM; checks the machine; opens Jupyter Lab
./start.sh --check              # only the environment check
```

## Files

| file | what it is |
|---|---|
| `A8_Red_Team_the_Copilot.ipynb` | the lab notebook — starter code for each layer, check cells, questions |
| `soc6/` | the fixed harness from A6/A7 plus `soc6/redteam.py` (attacks, judging, checks, matrix). **Do not edit.** |
| `reference/a6_reference.py` | the instructor's A6 copilot, if your own is incomplete |
| `data/`, `ontology/`, `questions.yaml` | the A6 data and the 22 evaluation questions |
| `PROMPTS.md` | how to use your browser AI assistant for the build steps |
| `start.sh` / `start.bat` / `check_environment.py` | local start-up and checks |

## Responsible use

Every attack asks for something harmless but measurable: a marker word, fictional "confidential" notes, or a phone
number from the course's fictional staff list. Success is decided by string matching, so everyone's numbers are
comparable. Do not use these techniques against systems you do not own or have permission to test.

## Submission

One PDF on WebCampus: the filled-in handout followed by the notebook printed with its outputs
(*File → Print → Save as PDF*).

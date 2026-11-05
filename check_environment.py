"""CS 789 A8 environment check: python check_environment.py"""
import importlib
import shutil
import sys
from pathlib import Path

ok = True


def line(name, good, detail=""):
    global ok
    ok &= bool(good)
    print(f"  [{'OK' if good else '!!'}] {name:30s} {detail}")


print("CS 789 A8 environment check")
line("python >= 3.10", sys.version_info >= (3, 10), sys.version.split()[0])
for mod in ["llama_index.core", "llama_index.llms.openai_like", "langchain", "langchain_community", "langchain_openai",
            "sqlalchemy", "rdflib", "pyshacl", "pyvis", "plotly", "fastapi", "uvicorn", "networkx", "yaml", "pandas"]:
    try:
        m = importlib.import_module(mod)
        line(mod, True, getattr(m, "__version__", ""))
    except Exception as e:
        line(mod, False, f"missing ({e.__class__.__name__}) -> pip install -r requirements.txt")
here = Path(__file__).parent
line("data/alerts.csv.gz", (here / "data" / "alerts.csv.gz").exists())
line("ontology/soc.ttl", (here / "ontology" / "soc.ttl").exists())
gpu = shutil.which("nvidia-smi")
line("NVIDIA GPU", gpu, "found" if gpu else "none: the local models need a GPU -> use Colab")
venv = Path("/content/vllm-env") if Path("/content").is_dir() else here / "vllm-env"
line("vLLM env", (venv / "bin" / "vllm").exists(), str(venv) + ("" if (venv / "bin" / "vllm").exists() else "  -> bash install_vllm.sh"))
try:
    import soc6.redteam as R
    line("soc6.redteam (A8 harness)", True, f"{len(R.ATTACKS)} attacks, {len(R.HELDOUT)} held-out")
except Exception as e:
    line("soc6.redteam", False, str(e))
line("my_a6.py (your A6 copilot)", (here / "my_a6.py").exists(), "" if (here / "my_a6.py").exists() else "upload it, or use the reference")
print("ALL GOOD" if ok else "Fix the [!!] lines above (vLLM is installed by the notebook on Colab).")

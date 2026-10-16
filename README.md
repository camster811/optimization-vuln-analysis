# Optimization vulnerability analysis

Development repository for studying how GCC optimization and symbol stripping
affect buffer-overflow recognition in binary functions.

- `pipeline/` and `ghidra/`: build, extraction, analysis, and validation code.
- `corpus/`: C source pairs and their manifest.
- `tests/`: regression and integration tests.
- `paper/`: research notes, reviews, and qualitative examples.
- [campaigns/](campaigns/README.md): versioned experiments and archives.
- [analysis_plan.md](analysis_plan.md): experiment design and scoring rules.


## Workflows
Reproduce numbers from saved prediction: Restore GCC-ABI-v2 and verify its outputs
Generate fresh predictions with a chosen model:	Create a new campaign using the latest root code

### The commands below run in Linux/WSL Bash, starting from the repository root.
1. Set up the environment
-  For byte-for-byte reproduction, match the saved environment: Python 3.14.4, the pinned requirements, and Pillow 12.3.0.
```sh
python3.14 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt Pillow==12.3.0 pytest
```
New users also need the campaign archive distributed alongside the latest repository.

2. To reproduce my saved results
- Check the archive’s SHA-256 against campaigns/gcc-abi-v2.json, then restore it into a fresh directory:
```sh
sha256sum campaigns/gcc-abi-v2.tar.gz
snapshot=$(mktemp -d)
tar -xzf campaigns/gcc-abi-v2.tar.gz -C "$snapshot"

python "$snapshot/pipeline/freeze.py" check
python "$snapshot/pipeline/evaluate.py" --check
```

The evaluation command regenerates the outputs temporarily and compares them with the saved artifacts. Expected results:
| Analyzer | Correct | Incorrect | Abstentions |
| -------- | ------- | --------- | ----------- |
|   LLM    |    57	 |    12	   |     11      |
|  Static  | 	  24   |   	0      |    	56     |

This uses the saved 240 LLM attempts. It requires no running LLM, GPU, or Ghidra.

### 3. To run a fresh campaign using the latest code
Follow these steps after environment setup.
1. Make the original binary artifacts available.
   campaign.py prepare copies existing binaries. On a fresh checkout without build/, restore the archive as above, then:
```bash
   if [ ! -d build ]; then
       cp -a "$snapshot/build" ./build
   fi
```
   This reuses the original machine-code inputs. Rebuilding from C is a separate reproducibility step requiring the configured GCC 15.2.0 and binutils 2.46, plus verification of the resulting artifacts.
   
2. Configure Ghidra and check the latest code.
   Use Ghidra 12.1.4:
   export GHIDRA_HOME=/absolute/path/to/ghidra_12.1.4_PUBLIC
   python -m pytest
   
3. Create a new campaign.
   Choose a destination that does not already exist:
   campaign=campaigns/my-model-v3
   python pipeline/campaign.py prepare --destination "$campaign"
   This copies the latest pipeline, including the frozen-input and interpreter fixes, into an isolated workspace.
   
4. Configure the model before freezing anything.
   Edit the new campaign’s config.json:
   | Field	| Set it to |
   | ------ | --------- |
   |llm.model_id |	Your model’s identifier |
   |llama_cpp.home |	Absolute path to your llama.cpp directory |
   |llama_cpp.model |	GGUF path relative to that directory |
   |llama_cpp.model_sha256 |	SHA-256 of that GGUF | 
   |llm.base_url |	Your local server address; default is http://127.0.0.1:8080 |
   
   
   Calculate the model hash with:
   ```sh
   sha256sum /absolute/path/to/model.gguf
   ```
   For my original model, use DeepSeek-R1-Distill-Qwen-14B-Q5_K_M and retain its configured hash. For a comparison against another model, retain the prompt, scoring, seeds, repetitions, and sampling settings where supported. Document changes in the campaign’s analysis_plan.md.
   Current compatibility limit: the runner expects local llama.cpp, a GGUF model, NVIDIA GPU execution with full GPU offload, and the configured deepseek reasoning format. Other reasoning formats, CPU execution, and hosted APIs need code changes before campaign preparation/freezing.
   
5. Generate the 80 corrected Ghidra exports.
   ```sh
   python pipeline/campaign.py extract --destination "$campaign"
   ```
   This selects the GCC ABI and checks instruction/call consistency against the original exports.
   
6. Start the model server and capture runtime evidence.
   The launcher expects build/bin/llama-server under llama_cpp.home.
```sh
   python "$campaign/pipeline/serve_llm.py" \
       > /tmp/my-model-v3-server.log 2>&1 &
   server_pid=$!
```
   Wait until the server is ready. With the default address, check:
```sh
   curl -f http://127.0.0.1:8080/health
```
   Then capture the server identity and validate token budgets:
```sh 
   python "$campaign/pipeline/runtime.py" \
       --pid "$server_pid" \
       --startup-log /tmp/my-model-v3-server.log
```

7. Freeze the campaign, then run both analyzers.
```sh
   python "$campaign/pipeline/freeze.py" create
   python "$campaign/pipeline/freeze.py" check
   
   python "$campaign/pipeline/static_baseline.py" \
       --inputs "$campaign/data/records" \
       --output "$campaign/results/static_predictions.jsonl"
   
   python "$campaign/pipeline/run_llm.py"
```
   The LLM runner performs 80 observations × 3 repetitions = 240 attempts. Use its default input directory. Keep the same server process running throughout inference.
   
8. Generate and verify the results.
```sh
   python "$campaign/pipeline/evaluate.py"
   python "$campaign/pipeline/evaluate.py" --check
   kill "$server_pid"
```
   Reports, diagnostics, figures, and the release manifest appear in the new campaign’s results/ directory.

"""Running simulation jobs for the evaluation scripts: a process pool, an append-only checkpoint
(an interrupted invocation resumes), and reuse of an earlier invocation's runs. A run is identified
by its spec hash and seed; checkpointed and reused runs are accepted only if they were produced by
the same code (provenance.code_hash), so a code change can never admit stale results."""
import gzip
import hashlib
import json
import multiprocessing as mp
import pathlib
from dataclasses import asdict

from .provenance import code_hash
from .sim import run_sim


def spec_key(spec):
    d = asdict(spec)
    d.pop("seed")
    d["features"] = sorted(d["features"])
    return json.dumps(d, sort_keys=True, default=str)


def spec_hash(spec):
    return hashlib.sha1(spec_key(spec).encode()).hexdigest()[:12]


def _job_indexed(item):
    i, spec = item
    return i, run_sim(spec)


class JobRunner:
    def __init__(self, procs=None, checkpoint=None, reuse=None, code_extra=()):
        self.procs = procs
        self.code = code_hash(code_extra)
        self.counts = {"run": 0, "resumed": 0, "reused": 0, "stale_rejected": 0}
        self.reuse_wall_s = 0.0
        self.checkpoint = pathlib.Path(checkpoint) if checkpoint else None
        self.loaded = self._load_checkpoint() if self.checkpoint else {}
        self.reuse = self._load_reuse(pathlib.Path(reuse)) if reuse else {}

    def _accept(self, row):
        if row.get("code_hash") != self.code:
            self.counts["stale_rejected"] += 1
            return False
        return True

    def _load_checkpoint(self):
        out = {}
        if self.checkpoint.exists():
            with open(self.checkpoint) as f:
                for line in f:
                    try:
                        row = json.loads(line)
                    except json.JSONDecodeError:              # a line cut off by the interruption
                        continue
                    if self._accept(row):
                        out[(row["spec_hash"], row["seed"])] = row["result"]
        return out

    def _load_reuse(self, path):
        out = {}
        prior = path.with_name(path.name.replace("_runs.jsonl.gz", ".json"))
        if prior.exists():
            self.reuse_wall_s = json.loads(prior.read_text())["meta"].get("wall_s", 0.0)
        with gzip.open(path, "rt") as f:
            for line in f:
                r = json.loads(line)
                if not self._accept(r):
                    continue
                key = (r.pop("spec_hash"), r["spec"]["seed"])
                for k in ("study", "index", "code_hash"):
                    r.pop(k, None)
                out[key] = r
        return out

    def run(self, specs):
        """Longest runs first; results in input order."""
        res = [None] * len(specs)
        todo = []
        for i, sp in enumerate(specs):
            key = (spec_hash(sp), sp.seed)
            if key in self.reuse:
                res[i] = self.reuse[key]; self.counts["reused"] += 1
            elif key in self.loaded:
                res[i] = self.loaded[key]; self.counts["resumed"] += 1
            else:
                todo.append(i)
        if self.loaded or self.reuse:
            print(f"  reused {self.counts['reused']}, resumed {self.counts['resumed']}, running {len(todo)} "
                  f"(stale rows rejected: {self.counts['stale_rejected']})", flush=True)
        order = sorted(todo, key=lambda i: -(specs[i].minutes + specs[i].warmup_minutes
                                             + 60 * 24 * 7 * specs[i].profile_weeks / 60))
        ck = open(self.checkpoint, "a") if self.checkpoint else None
        with mp.Pool(self.procs or mp.cpu_count()) as pool:
            for i, r in pool.imap_unordered(_job_indexed, [(i, specs[i]) for i in order], chunksize=1):
                res[i] = r
                self.counts["run"] += 1
                if ck:
                    ck.write(json.dumps({"spec_hash": spec_hash(specs[i]), "seed": specs[i].seed, "code_hash": self.code,
                                         "result": r}, default=str) + "\n")
                    ck.flush()
        if ck:
            ck.close()
        return res

    def meta(self):
        """For the results' metadata: how this invocation's runs were obtained."""
        kind = "clean" if not (self.counts["resumed"] or self.counts["reused"]) else \
            ("resumed" if not self.counts["reused"] else "reused")
        return {"code_hash": self.code, "invocation": kind, **self.counts}

    def write_runs(self, path, jobs, results):
        with gzip.open(path, "wt") as f:
            for (study, idx, spec), r in zip(jobs, results):
                r = dict(r); r["study"] = study; r["index"] = idx
                r["spec_hash"] = spec_hash(spec); r["code_hash"] = self.code
                f.write(json.dumps(r, default=str) + "\n")

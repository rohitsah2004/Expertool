"""Offline 64-KiB redaction microbenchmark; no network or real credentials."""
import argparse
import json
import platform
from pathlib import Path
import statistics
import sys
import time

sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
import expertool.redaction as redaction


def benchmark(iterations=300):
    # Exercise a full cache, including a hit at the end of a response body.
    for n in range(redaction.MAX_SECRETS):
        redaction.register_credentials({'Authorization':f'synthetic-credential-{n:04d}-F1uQ'})
    token=f'synthetic-credential-{redaction.MAX_SECRETS-1:04d}-F1uQ'
    bodies={'plain':'x'*65536,'json':json.dumps({'description':'x'*(65536-len(json.dumps({'description':''},separators=(',',':'))))},separators=(',',':')),
            'registered_value':'x'*(65536-len(token)-1)+' '+token}
    result={'platform':platform.system(),'python':platform.python_version(),'iterations':iterations,'cache_entries':len(redaction._SECRETS),'cases':{}}
    for name,body in bodies.items():
        redaction.redact_text(body) # Warm compiled pattern cache outside timed calls.
        samples=[]
        for _ in range(iterations):
            start=time.perf_counter_ns();redaction.redact_text(body);samples.append((time.perf_counter_ns()-start)/1e6)
        result['cases'][name]={'bytes':len(body.encode()),'mean_ms':round(statistics.mean(samples),4),
            'median_ms':round(statistics.median(samples),4),'p95_ms':round(sorted(samples)[int(.95*(len(samples)-1))],4)}
    result['under_1ms_mean']=all(case['mean_ms']<1 for case in result['cases'].values())
    return result

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--iterations',type=int,default=300);args=parser.parse_args()
    if not 10<=args.iterations<=10000:parser.error('iterations must be 10–10000')
    print(json.dumps(benchmark(args.iterations),indent=2))

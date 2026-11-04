"""Execute a trusted UI job from frozen source; credentials stay in controller memory."""
import argparse
import json
from pathlib import Path

from research_core import load
from .budget_recover import recover
from .storage import save


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',required=True)
    args=parser.parse_args()
    config=load(args.config)
    result=recover(config['input'],config['context'],config['target'],config['available_at'],config['out'],
        policy=config['policy'],budget=config['budget'],streaming=config['streaming'],
        advisory_snapshot=config['advisory_snapshot'],code=config['code'],image=config['image'])
    save(Path(config['out'])/'result.json',result)
    print(json.dumps(result))


if __name__=='__main__':main()

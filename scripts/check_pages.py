"""Check that live GitHub Pages serves the exact committed static source.

Uses normal TLS verification and inherited proxy/CA settings. This checks deployed
bytes, not browser behavior; the separate Chromium test checks the same artifacts.
"""
import argparse
import hashlib
from pathlib import Path
import httpx


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url',default='https://mitchell-d00.github.io/OwnerGate/')
    args=parser.parse_args()
    root=Path(__file__).resolve().parents[1]
    with httpx.Client(timeout=30,follow_redirects=True) as client:
        for name in ['index.html','site/app.js','site/demo.js','site/style.css','site/icon.svg']:
            response=client.get(args.url.rstrip('/')+'/'+('' if name=='index.html' else name),headers={'Cache-Control':'no-cache'})
            response.raise_for_status()
            expected=hashlib.sha256((root/name).read_bytes()).hexdigest()
            actual=hashlib.sha256(response.content).hexdigest()
            if expected != actual:
                raise SystemExit('Live content mismatch: '+name+' (deployment/CDN may still be updating)')
            print('PASS deployed SHA-256',name,actual)
    print('GitHub Pages serves the exact verified static artifacts.')


if __name__=='__main__':main()

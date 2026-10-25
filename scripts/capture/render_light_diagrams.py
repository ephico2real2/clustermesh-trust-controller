#!/usr/bin/env python3
"""Capture only light PNGs after diagram-kit --check validates the source page."""
import argparse
from pathlib import Path
import re
import tempfile

from playwright.sync_api import sync_playwright


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('names', help='Comma-separated names, one per .fig-scroll')
    args = parser.parse_args()
    names = args.names.split(',')
    if not names or len(names) != len(set(names)) or any(
        re.fullmatch(r'[a-z0-9]+(?:-[a-z0-9]+)*', name) is None for name in names
    ):
        parser.error('Use unique lowercase figure names without paths')
    source = args.source.resolve(strict=True)
    args.output.mkdir(parents=True, exist_ok=True)
    targets = [args.output / (name + '.light.png') for name in names]
    if any(path.is_symlink() or (path.exists() and not path.is_file()) for path in targets):
        parser.error('Refuse symlink or non-file image targets')
    # Stage only light images. A browser failure cannot leave partial final PNGs.
    with tempfile.TemporaryDirectory(prefix='cmtc-light-', dir=args.output) as temporary:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            try:
                page = browser.new_page(
                    viewport={'width': 1200, 'height': 1500}, device_scale_factor=2,
                    color_scheme='light',
                )
                page.goto(source.as_uri(), wait_until='networkidle', timeout=60000)
                page.evaluate("document.documentElement.dataset.theme = 'light'")
                page.evaluate('() => document.fonts.ready.then(() => true)')
                figures = page.locator('.fig-scroll')
                if figures.count() != len(names):
                    raise RuntimeError('Figure count does not match the requested names')
                for index, name in enumerate(names):
                    figures.nth(index).screenshot(
                        path=str(Path(temporary) / (name + '.light.png')), type='png',
                    )
            finally:
                browser.close()
        for name, target in zip(names, targets):
            (Path(temporary) / (name + '.light.png')).replace(target)
            print('wrote', target)


if __name__ == '__main__':
    main()

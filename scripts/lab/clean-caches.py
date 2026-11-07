#!/usr/bin/env python3
"""Reclaim disk from build caches on a CMTC development host, on Linux and macOS. Dry run unless --delete.

Builds here write Go, Cargo and lint caches under the temporary directory (/private/tmp on macOS, /tmp on Linux),
Go's own cache, Docker build caches, buildkit builders and cache volumes. All of it is regenerable: a deleted cache
only makes the next build slower. What it reclaims:

  host        cache directories in the temporary directory, by name (CACHE_NAMES), and image tarballs (*.tar) and Go
              test binaries (*.test) at its top level; then Go's own cache (go clean -cache)
  docker      for each --docker-context: the build cache (docker builder prune), every buildkit builder container's
              cache (buildctl prune), unused volumes named like a cache, and with --images, images no container uses
  trim        fstrim of each Colima VM's Docker disk, so the VM's disk file on the host shrinks too (a Colima disk
              is a sparse file that never shrinks by itself)

It never touches a running container's image or volume (so never a kind node), the lab kubeconfig, the review area,
agent session folders, or a source tree: a directory is a cache only by its name. --min-age-hours keeps anything
written more recently (default 24) in the temporary directory and among images. It refuses to delete while a build runs (go, cargo, rustc, docker or podman
build), because a build reads its cache.

Usage: scripts/lab/clean-caches.py [--delete] [--images] [--docker-context NAME]... [--min-age-hours H]
"""
import argparse
import fnmatch
import json
import os
import pathlib
import platform
import shutil
import subprocess
import sys
import time

CACHE_NAMES = ('*go-cache', '*-gocache', '*go-build-cache', '*-mod-cache', '*go-modules', '*-go-mod',
               '*cargo-cache', '*cargo-home', '*lint-cache', '*bpf-cache')
ARTIFACT_NAMES = ('*.tar', '*.test')
# Never deleted, whatever their name: lab credentials, the review area with leases and evidence, agent sessions.
PROTECTED = ('*.kubeconfig', 'cmtc-opus-final-*', 'claude-*', 'codex-*')
VOLUME_NAMES = ('*go-cache', '*-gocache', '*cargo-cache', '*mod-cache')
BUILD_COMMANDS = (('go', ('build', 'test', 'vet', 'install', 'run')), ('cargo', ()), ('rustc', ()),
                  ('docker', ('build', 'buildx')), ('podman', ('build',)))


def temp_root() -> pathlib.Path:
    return pathlib.Path('/private/tmp' if platform.system() == 'Darwin' else '/tmp')


def matches(name: str, patterns) -> bool:
    return any(fnmatch.fnmatch(name, p) for p in patterns)


def last_write(path: pathlib.Path) -> float:
    """Newest mtime of path and its direct children: a Go cache writes into fixed subdirectories 00..ff."""
    newest = path.lstat().st_mtime
    if path.is_dir() and not path.is_symlink():
        with os.scandir(path) as entries:
            for e in entries:
                try:
                    newest = max(newest, e.stat(follow_symlinks=False).st_mtime)
                except OSError:
                    pass
    return newest


def size_kib(path: pathlib.Path) -> int:
    out = subprocess.run(['du', '-sk', str(path)], capture_output=True, text=True, env=dict(os.environ, LC_ALL='C'))
    return int(out.stdout.split()[0]) if out.returncode == 0 and out.stdout else 0


def host_candidates(root: pathlib.Path, min_age_s: float) -> list[pathlib.Path]:
    now, out = time.time(), []
    for p in sorted(root.iterdir()):
        name = p.name
        if p.is_symlink() or matches(name, PROTECTED):
            continue
        cache = p.is_dir() and matches(name, CACHE_NAMES)
        artifact = p.is_file() and matches(name, ARTIFACT_NAMES)
        if (cache or artifact) and now - last_write(p) >= min_age_s:
            out.append(p)
    return out


def remove_tree(path: pathlib.Path) -> None:
    # Go's module cache is read-only; give the owner write access back before removing.
    if path.is_dir():
        for d, dirs, _ in os.walk(path):
            for x in [d] + [os.path.join(d, n) for n in dirs]:
                try:
                    os.chmod(x, os.stat(x, follow_symlinks=False).st_mode | 0o700)
                except OSError:
                    pass
        shutil.rmtree(path)
    else:
        path.unlink()


def running_builds() -> list[str]:
    out = subprocess.run(['ps', '-axo', 'pid=,args='], capture_output=True, text=True, check=True).stdout
    found = []
    for line in out.splitlines():
        pid, _, args = line.strip().partition(' ')
        words = args.split()
        if not words or int(pid) == os.getpid():
            continue
        cmd = os.path.basename(words[0])
        for name, subcommands in BUILD_COMMANDS:
            if cmd == name and (not subcommands or any(w in subcommands for w in words[1:3])):
                found.append(f'{pid} {args[:120]}')
    return found


class Docker:
    def __init__(self, context: str):
        self.context = context

    def run(self, *args: str, check: bool = True) -> str:
        r = subprocess.run(['docker', '--context', self.context, *args], capture_output=True, text=True)
        if check and r.returncode:
            raise SystemExit(f'docker --context {self.context} {" ".join(args[:3])}: {r.stderr.strip()}')
        return r.stdout

    def df(self) -> str:
        return self.run('system', 'df')

    def buildkit_containers(self) -> list[str]:
        out = self.run('ps', '--format', '{{.Names}} {{.Image}}')
        return [n for n, _, image in (l.partition(' ') for l in out.splitlines()) if image.startswith('moby/buildkit')]

    def cache_volumes(self) -> list[str]:
        names = [v for v in self.run('volume', 'ls', '-q').split() if matches(v, VOLUME_NAMES)]
        return [v for v in names if not self.run('ps', '-aq', '--filter', f'volume={v}').strip()]


def colima_profile(context: str) -> str | None:
    return context.removeprefix('colima-') if context.startswith('colima-') else None


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0], epilog=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--delete', action='store_true', help='delete; without it, only report')
    ap.add_argument('--images', action='store_true', help='also remove images that no container uses')
    ap.add_argument('--docker-context', action='append', default=[],
                    help='Docker context to clean (repeatable; default: the current context)')
    ap.add_argument('--min-age-hours', type=float, default=24.0)
    ap.add_argument('--no-docker', action='store_true')
    args = ap.parse_args()
    min_age_s = args.min_age_hours * 3600
    hours = f'{args.min_age_hours:g}h'

    builds = running_builds()
    if builds and args.delete:
        print('a build is running; nothing deleted:', *builds, sep='\n  ')
        sys.exit(2)

    root = temp_root()
    host = host_candidates(root, min_age_s)
    total = 0
    for p in host:
        kib = size_kib(p)
        total += kib
        print(f'host    {kib / 1048576:7.1f}G  {p}')
        if args.delete:
            remove_tree(p)
    print(f'host    {total / 1048576:7.1f}G  in {len(host)} item(s) under {root}, written {hours}+ ago')
    if shutil.which('go'):
        gocache = subprocess.run(['go', 'env', 'GOCACHE'], capture_output=True, text=True).stdout.strip()
        if gocache and pathlib.Path(gocache).is_dir():
            print(f'go      {size_kib(pathlib.Path(gocache)) / 1048576:7.1f}G  {gocache} (go clean -cache)')
            if args.delete:
                subprocess.run(['go', 'clean', '-cache'], check=True)

    if args.no_docker or not shutil.which('docker'):
        return
    contexts = args.docker_context or [json.loads(subprocess.run(
        ['docker', 'context', 'inspect'], capture_output=True, text=True, check=True).stdout)[0]['Name']]
    for context in contexts:
        d = Docker(context)
        print(f'\ndocker  {context}\n{d.df()}')
        builders, volumes = d.buildkit_containers(), d.cache_volumes()
        print(f'docker  all build cache; buildkit builders {builders or "none"}; '
              f'cache volumes {volumes or "none"}' + ('; images no container uses' if args.images else ''))
        if not args.delete:
            continue
        # --all: without it both prune only dangling records, and most of a build cache is not dangling. No age
        # filter: measured on Docker 29.5, `until=24h` kept 16.9 GB of records last used two days earlier. A build
        # cache is pruned only while no build runs (checked above).
        d.run('builder', 'prune', '--all', '--force')
        for b in builders:
            d.run('exec', b, 'buildctl', 'prune', '--all')
        for v in volumes:
            d.run('volume', 'rm', v)
        if args.images:
            # docker refuses to remove an image a container uses, running or stopped.
            d.run('image', 'prune', '--all', '--force', '--filter', f'until={hours}')
        print(d.df())
        profile = colima_profile(context)
        if profile and shutil.which('colima'):
            # util-linux fstrim takes one mount point per call.
            for mount in ('/var/lib/docker', '/'):
                trimmed = subprocess.run(['colima', 'ssh', '-p', profile, '--', 'sudo', 'fstrim', '-v', mount],
                                         capture_output=True, text=True)
                print(f'trim    {trimmed.stdout.strip() or trimmed.stderr.strip()}')


if __name__ == '__main__':
    main()

"""Runner for katana: executes katana with -jsonl and streams stdout to a file.

katana (recent versions) emits JSONL only to stdout, and — crucially — Go
block-buffers stdout when it is a regular file but flushes when it is a pipe.
So we capture stdout through a PIPE and write each line to the output file
ourselves (immediate flush). A wall-clock timer bounds the crawl.
"""

import argparse
import shutil
import subprocess
import sys
import threading


def main():
    ap = argparse.ArgumentParser(prog="techrecon-katana")
    ap.add_argument("-l", "--list", required=True)
    ap.add_argument("-o", "--output", required=True)
    ap.add_argument("-t", "--timeout", type=int, default=10)
    ap.add_argument("-c", "--concurrency", type=int, default=10)
    ap.add_argument("-d", "--depth", type=int, default=2)
    ap.add_argument("--rate-limit", type=int, default=0)
    ap.add_argument("--max-wall", type=int, default=1800, help="overall crawl time budget (s)")
    args = ap.parse_args()

    katana = shutil.which("katana") or "katana"
    cmd = [
        katana,
        "-list", args.list,
        "-jsonl",
        "-d", str(args.depth),
        "-c", str(args.concurrency),
        "-timeout", str(args.timeout),
        "-silent",
        "-no-color",
    ]
    if args.rate_limit > 0:
        cmd.extend(["-rl", str(args.rate_limit)])

    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=1, text=True
        )
    except FileNotFoundError:
        sys.stderr.write("katana binary not found\n")
        return

    killer = threading.Timer(args.max_wall, proc.kill)
    killer.start()
    try:
        with open(args.output, "w") as out:
            # readline() avoids the read-ahead buffering of `for line in proc.stdout`,
            # which can block indefinitely on a slow pipe.
            while True:
                line = proc.stdout.readline()
                if not line:
                    break
                out.write(line)
                out.flush()
    finally:
        killer.cancel()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    main()

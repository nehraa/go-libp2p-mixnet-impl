#!/usr/bin/env python3
import argparse
import curses
import os
import queue
import re
import subprocess
import threading
import time
from pathlib import Path


ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
STEP_RE = re.compile(r"\[(\d+)/(\d+)\]\s*(?:\[[=\-]*\]\s*)?(.+)$")


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


class DashboardState:
    def __init__(self, mode: str):
        self.mode = mode
        self.total_steps = 22
        self.current_step = 0
        self.current_name = "bootstrapping"
        self.scene = "boot"
        self.logs = []
        self.max_logs = 2000
        self.start = time.time()
        self.end = None
        self.done = False
        self.exit_code = None
        self.pass_count = 0
        self.fail_count = 0
        self.spinner_i = 0
        self.last_scene = "boot"

    def add_log(self, line: str):
        plain = strip_ansi(line.rstrip())
        self.logs.append(plain)
        if len(self.logs) > self.max_logs:
            self.logs = self.logs[-self.max_logs :]
        self._parse_line(plain)

    def _parse_line(self, line: str):
        if line.startswith("--- PASS:"):
            self.pass_count += 1
        elif line.startswith("--- FAIL:"):
            self.fail_count += 1

        if line.startswith("=== RUN   TestProductionSanity/"):
            sub = line.split("TestProductionSanity/", 1)[1].strip()
            self.current_name = sub
            self.scene = infer_scene(sub)
            self.last_scene = self.scene

        m = STEP_RE.search(line)
        if m:
            self.current_step = int(m.group(1))
            self.total_steps = int(m.group(2))
            self.current_name = m.group(3).strip()
            self.scene = infer_scene(self.current_name)
            self.last_scene = self.scene

    def tick(self):
        self.spinner_i = (self.spinner_i + 1) % 4

    @property
    def elapsed(self) -> float:
        end = self.end if self.end is not None else time.time()
        return end - self.start


def infer_scene(name: str) -> str:
    n = name.lower()
    if "failure_and_recover_from_failure" in n or "recover" in n:
        return "recovery"
    if "close" in n:
        return "close"
    if "header-only" in n or "header_only" in n:
        return "header"
    if "full_onion" in n or "full onion" in n:
        return "full_onion"
    if "key_exchange" in n or "key exchange" in n:
        return "key"
    if "ces" in n:
        return "ces"
    if "onion" in n or "decrypt" in n:
        return "onion"
    if "circuit" in n or "relay" in n or "stream" in n:
        return "hops"
    if "docker" in n:
        return "docker"
    return "net"


def build_cmd(mode: str, verbose_runtime_logs: bool):
    script_dir = Path(__file__).resolve().parent
    mixnet_root = script_dir.parent
    repo_root = mixnet_root.parent

    env = os.environ.copy()
    env["MIXNET_SANITY_VERBOSE_LOGS"] = "1" if verbose_runtime_logs else "0"

    if mode == "local":
        return (
            ["go", "test", "./mixnet/core", "-count=1", "-v", "-run", "^TestProductionSanity$"],
            str(repo_root),
            env,
        )
    env["TARGET_TEST"] = "TestProductionSanity"
    return (
        ["bash", "mixnet/tests/docker/run-docker-tests.sh"],
        str(repo_root),
        env,
    )


def reader_thread(proc: subprocess.Popen, out_q: queue.Queue):
    assert proc.stdout is not None
    for line in proc.stdout:
        out_q.put(line)
    out_q.put(None)


def progress_bar(width: int, cur: int, total: int) -> str:
    total = max(total, 1)
    cur = max(0, min(cur, total))
    fill = int((cur / total) * width)
    return "[" + ("#" * fill) + ("-" * (width - fill)) + "]"


def scene_lines(state: DashboardState, width: int):
    frame = state.spinner_i
    dots = "." * ((frame % 3) + 1)
    pulse = "●" if frame % 2 == 0 else "◉"
    if state.scene == "key":
        return [
            f"Key Exchange {dots}",
            f"  [Origin {pulse}] ---(ephemeral key)---> [Relay] ---(shared secret)---> [Dest]",
            "  Handshake: Noise IK | Session: AES-GCM | Auth Tag: ON",
        ]
    if state.scene == "ces":
        shard = frame % 3
        marker = [" ", " ", " "]
        marker[shard] = "*"
        return [
            f"CES Pipeline {dots}",
            f"  Shards: [{marker[0]}1] [{marker[1]}2] [{marker[2]}3]  ->  Reconstruct @ Destination",
            "  FEC + Retry + Integrity Check",
        ]
    if state.scene == "full_onion":
        ring = ["(((())))", "((()))", "(())", "()", "payload"]
        layer = ring[frame % len(ring)]
        return [
            f"Full Onion Path {dots}",
            f"  Encrypt: payload -> {layer}",
            "  Hop decrypt chain: Entry -> Middle -> Exit -> Destination",
        ]
    if state.scene == "header":
        return [
            f"Header-Only Onion {dots}",
            "  Header encrypted, payload transport direct",
            "  Fast-path routing with privacy header protection",
        ]
    if state.scene == "onion":
        peel = max(0, 4 - (frame % 5))
        return [
            f"Onion Decryption {dots}",
            "  Layers: " + ("(" * peel) + "payload" + (")" * peel),
            "  Header-only + Full Onion paths verified",
        ]
    if state.scene == "recovery":
        fail_hop = frame % 3 + 1
        new_hop = (fail_hop % 3) + 1
        return [
            f"Failure Recovery {dots}",
            f"  Circuit fail @ R{fail_hop}  ->  Rebuild with R{new_hop}",
            "  Mark failed relay, reselect hops, restore stream path",
        ]
    if state.scene == "close":
        spinner = ["↻", "↺", "↻", "✓"][frame % 4]
        return [
            f"Circuit Close / Ack {dots}",
            f"  Sending close frames {spinner} waiting for close-ack",
            "  Drain streams, stop notifier, disconnect peers cleanly",
        ]
    if state.scene == "hops":
        hop = frame % 5
        nodes = ["Origin", "R1", "R2", "R3", "Dest"]
        parts = []
        for i, node in enumerate(nodes):
            token = f"[{node}]"
            if i == hop:
                token = ">" + token + "<"
            parts.append(token)
        return [
            f"Relay Hops {dots}",
            "  " + " -> ".join(parts),
            "  Circuit setup | stream open | forward | close",
        ]
    if state.mode == "docker":
        return [
            f"Docker Mesh {dots}",
            "  Containers: origin + destination + 7 relays",
            "  Network: bridge subnet 10.10.0.0/16",
        ]
    return [
        f"Sanity Runner {dots}",
        "  Config | Discovery | Circuit | CES | Onion | Recovery | Close",
        "  Local libp2p test orchestration",
    ]


def draw(stdscr, state: DashboardState):
    def safe_addnstr(row: int, col: int, text: str, n: int, attr=0):
        h, w = stdscr.getmaxyx()
        if row < 0 or row >= h or col < 0 or col >= w:
            return
        try:
            stdscr.addnstr(row, col, text, n, attr)
        except curses.error:
            pass

    stdscr.erase()
    h, w = stdscr.getmaxyx()
    if h < 8 or w < 40:
        safe_addnstr(0, 0, "Terminal too small for dashboard. Resize and retry.", max(1, w - 1))
        stdscr.refresh()
        return

    top_h = h // 2
    if top_h < 6:
        top_h = 6
    if top_h > h - 3:
        top_h = h - 3

    title = f"Mixnet Test Dashboard [{state.mode}]"
    safe_addnstr(0, 0, title.ljust(w), max(1, w - 1), curses.A_BOLD)
    status = "RUNNING" if not state.done else ("PASS" if state.exit_code == 0 else "FAIL")
    elapsed = f"{state.elapsed:0.1f}s"
    safe_addnstr(1, 0, f"Status: {status}   Elapsed: {elapsed}".ljust(w), max(1, w - 1))

    bar_w = max(20, min(60, w - 30))
    bar = progress_bar(bar_w, state.current_step, state.total_steps)
    safe_addnstr(
        2,
        0,
        f"Progress: {bar} {state.current_step}/{state.total_steps}".ljust(w),
        max(1, w - 1),
    )
    safe_addnstr(3, 0, f"Step: {state.current_name}".ljust(w), max(1, w - 1))
    safe_addnstr(4, 0, f"Subtests: pass={state.pass_count} fail={state.fail_count}".ljust(w), max(1, w - 1))
    if state.done:
        safe_addnstr(5, 0, "Done. Press q (or Enter) to exit dashboard.".ljust(w), max(1, w - 1))

    lines = scene_lines(state, w)
    row = 7 if state.done else 6
    for line in lines:
        if row >= top_h - 1:
            break
        safe_addnstr(row, 0, line.ljust(w), max(1, w - 1))
        row += 1

    divider = "-" * w
    safe_addnstr(top_h - 1, 0, divider, max(1, w - 1))

    bottom_start = top_h
    bottom_h = h - bottom_start
    log_lines = state.logs[-bottom_h:]
    for i, line in enumerate(log_lines):
        safe_addnstr(bottom_start + i, 0, line[:w].ljust(w), max(1, w - 1))

    stdscr.refresh()


def run_dashboard(stdscr, mode: str, verbose_runtime_logs: bool):
    try:
        curses.curs_set(0)
    except curses.error:
        pass
    stdscr.nodelay(True)
    stdscr.timeout(100)

    cmd, cwd, env = build_cmd(mode, verbose_runtime_logs)
    state = DashboardState(mode)

    proc = subprocess.Popen(
        cmd,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    out_q = queue.Queue()
    t = threading.Thread(target=reader_thread, args=(proc, out_q), daemon=True)
    t.start()

    saw_end = False
    waiting_for_exit = False
    while True:
        state.tick()
        while True:
            try:
                item = out_q.get_nowait()
            except queue.Empty:
                break
            if item is None:
                saw_end = True
                break
            state.add_log(item)

        if saw_end and proc.poll() is not None:
            state.done = True
            state.exit_code = proc.returncode
            state.end = time.time()

        draw(stdscr, state)

        ch = stdscr.getch()
        if ch in (ord("q"), ord("Q")):
            if proc.poll() is None:
                proc.terminate()
            break

        if state.done:
            waiting_for_exit = True
            state.scene = state.last_scene

        if waiting_for_exit and ch in (ord("\n"), ord("\r"), 10, 13):
            break

    return state.exit_code if state.exit_code is not None else 0


def select_mode(arg_mode: str):
    if arg_mode:
        return arg_mode
    print("Select mode:")
    print("  1) local (go test TestProductionSanity)")
    print("  2) docker (tests/docker/run-docker-tests.sh)")
    choice = input("Enter choice [1/2]: ").strip()
    if choice == "2":
        return "docker"
    return "local"


def main():
    parser = argparse.ArgumentParser(description="Terminal dashboard for mixnet test runs.")
    parser.add_argument("--mode", choices=["local", "docker"], help="Run mode.")
    parser.add_argument(
        "--verbose-runtime-logs",
        action="store_true",
        help="Enable verbose runtime [Mixnet] logs inside tests.",
    )
    args = parser.parse_args()

    mode = select_mode(args.mode)
    exit_code = curses.wrapper(run_dashboard, mode, args.verbose_runtime_logs)
    raise SystemExit(exit_code)


if __name__ == "__main__":
    main()

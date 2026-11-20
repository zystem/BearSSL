#!/usr/bin/env python3
# Checks that the documents tell the truth where the program can be asked.
#
#  <!-- run -->       the next ```bash block is run from the repository
#                     directory; if a ```text block follows it, every line
#                     of that block must appear, in order, in the output
#                     (lines that the document cuts are simply not listed).
#  <!-- run-bg -->    the same, but the command is started in the
#                     background (a server) and its output is compared when
#                     the page is finished.
#  <!-- usage: CMD -->  the next ```text block must equal the output of
#                     CMD (lines starting with "ERROR:" are dropped).
# Also: every relative link between the documents must point to a file.
import os, re, signal, subprocess, sys, tempfile, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PAGES = ["README.md", "docs/howto-enable-tls13.md", "docs/howto-mutual-tls.md",
         "docs/howto-resumption.md", "docs/reference-brssl.md"]
ALL = PAGES + ["docs/README.md", "docs/reference-api.md", "docs/supported-versions.md",
               "docs/troubleshooting.md", "docs/faq.md", "docs/production-checklist.md",
               "docs/explanation-design.md", "docs/explanation-security-status.md",
               "docs/testing.md", "CHANGELOG.md", "contrib/nim/README.md",
               "CONTRIBUTING.md", "SECURITY.md", "GOVERNANCE.md", "CODE_OF_CONDUCT.md", "DCO.md",
               "docs/building.md", "docs/architecture.md", "docs/threat-model.md",
               "docs/security-policies.md", "docs/verifying-releases.md", "docs/releasing.md"]
fails = []
checked = 0


def fail(msg):
    fails.append(msg)
    print("FAIL:", msg)


def blocks(text):
    """yield (marker, lang, body) for each fenced block, marker being the
    html comment right before it (or None)"""
    out = []
    pat = re.compile(r"(?:<!-- (.*?) -->\n)?```(\w*)\n(.*?)```", re.S)
    for m in pat.finditer(text):
        out.append((m.group(1), m.group(2), m.group(3)))
    return out


def subseq(expected, actual):
    i = 0
    for line in actual:
        if i < len(expected) and line.rstrip() == expected[i].rstrip():
            i += 1
    return i == len(expected), (expected[i] if i < len(expected) else None)


def run(cmd, bg):
    f = tempfile.NamedTemporaryFile("w+", delete=False)
    p = subprocess.Popen(["bash", "-c", cmd], cwd=ROOT, stdin=subprocess.DEVNULL, stdout=f,
                         stderr=subprocess.STDOUT, text=True, start_new_session=True)
    p.outfile = f
    return p


def kill(p):
    try:
        os.killpg(p.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass


def lines_of(p, bg):
    """wait for the shell (a command that starts a server with & is done
    when the shell is), stop what is left of its group, read the output"""
    if bg:
        time.sleep(0.5)
    else:
        p.wait(timeout=60)
    kill(p)
    p.wait()
    p.outfile.flush()
    with open(p.outfile.name) as f:
        out = f.read()
    os.unlink(p.outfile.name)
    return out.splitlines()


def check_page(page):
    global checked
    text = open(os.path.join(ROOT, page)).read()
    bl = blocks(text)
    bgs = []
    for i, (marker, lang, body) in enumerate(bl):
        nxt = bl[i + 1] if i + 1 < len(bl) else None
        expected = None
        if nxt and nxt[1] == "text" and nxt[0] is None:
            expected = nxt[2].splitlines()
        if marker in ("run", "run-bg") and lang == "bash":
            bg = marker == "run-bg"
            p = run(body, bg)
            if bg:
                bgs.append((body, expected, p))
                time.sleep(2.5)
                continue
            try:
                out = lines_of(p, False)
            except subprocess.TimeoutExpired:
                kill(p)
                p.wait()
                fail("%s: command timed out: %s" % (page, body.splitlines()[0]))
                continue
            checked += 1
            if p.returncode != 0:
                fail("%s: exit status %d for: %s" % (page, p.returncode, body.splitlines()[0]))
            if expected is not None:
                ok, miss = subseq(expected, out)
                if not ok:
                    fail("%s: line not in the output: %r\n--- actual ---\n%s" % (page, miss, "\n".join(out)))
            time.sleep(0.3)
        elif marker and marker.startswith("usage: ") and lang == "text":
            cmd = marker[len("usage: "):]
            r = subprocess.run(["bash", "-c", cmd], cwd=ROOT, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, text=True)
            act = [l for l in r.stdout.splitlines() if not l.startswith("ERROR:")]
            checked += 1
            if act != body.splitlines():
                import difflib
                fail("%s: usage text differs for '%s':\n%s" % (page, cmd, "\n".join(
                    difflib.unified_diff(body.splitlines(), act, "document", "program", lineterm=""))))
    for body, expected, p in bgs:
        out = lines_of(p, True)
        checked += 1
        if expected is not None:
            ok, miss = subseq(expected, out)
            if not ok:
                fail("%s: line not in the output of the background command: %r\n--- actual ---\n%s"
                     % (page, miss, "\n".join(out)))
    # leftovers of the page
    subprocess.run("pgrep -x brssl | xargs -r kill; pgrep -x server_basic | xargs -r kill", shell=True,
                   stderr=subprocess.DEVNULL)


def check_links():
    global checked
    pat = re.compile(r"\]\(([^)#\s]+)(?:#[^)]*)?\)")
    for page in ALL:
        path = os.path.join(ROOT, page)
        if not os.path.exists(path):
            fail("missing page: " + page)
            continue
        for m in pat.finditer(open(path).read()):
            t = m.group(1)
            if re.match(r"\w+:", t):
                continue
            checked += 1
            if not os.path.exists(os.path.normpath(os.path.join(os.path.dirname(path), t))):
                fail("%s: link to a file that does not exist: %s" % (page, t))


def check_options():
    """every option in the usage text of the tools has a line in the reference"""
    global checked
    ref = open(os.path.join(ROOT, "docs/reference-brssl.md")).read()
    for cmd in ("client", "server"):
        r = subprocess.run([os.path.join(ROOT, "build/brssl"), cmd, "-h"], stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, text=True)
        for l in r.stdout.splitlines():
            m = re.match(r"   (-\w+)", l)
            if m:
                checked += 1
                if m.group(1) not in ref:
                    fail("option %s of 'brssl %s' is not in the reference" % (m.group(1), cmd))


def main():
    subprocess.run("pgrep -x brssl | xargs -r kill", shell=True)
    for page in PAGES:
        check_page(page)
    check_links()
    check_options()
    print("%d checks, %d failures" % (checked, len(fails)))
    return 1 if fails else 0


sys.exit(main())

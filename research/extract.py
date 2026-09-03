"""Pull the concrete operations a SKILL.md instructs an agent to perform.

IMPORTANT LIMITATION. The public dataset ships SKILL.md content with
newlines collapsed to spaces ("sanitized"). Fenced code blocks survive as
``` delimiters, but the individual commands inside a multi-command block
run together with no separator, so per-command counts are not recoverable.

Everything here therefore measures at *skill* granularity: does this skill
instruct at least one action of class X. That undercounts - a block with
five risky commands scores the same as one with a single risky command -
so every number downstream is a floor, not an estimate.

Prose is ignored entirely. "This skill can delete your notes" is a
sentence, not an action; only fenced content is treated as executable.
"""
import re

# Language tags that mark a fence as executable. A bare fence counts only
# if its content opens like a command, since bare fences also carry sample
# output, JSON, and file listings.
SHELL_LANGS = {"bash", "sh", "shell", "zsh", "console", "terminal", "shell-session"}

COMMAND_START = re.compile(
    r"^\s*(?:sudo\s+)?(?:curl|wget|git|npm|npx|pnpm|yarn|pip[0-9.]*|python[0-9.]*|node|go|cargo|"
    r"brew|apt|apt-get|docker|kubectl|gh|aws|gcloud|az|rm|cp|mv|mkdir|cat|echo|export|source|"
    r"chmod|chown|ssh|scp|rsync|tar|unzip|make|bash|sh|zsh|open|osascript|security|defaults|jq)\b"
)

PATH_LIKE = re.compile(
    r"(?<![\w/.-])((?:~|\$HOME|/[A-Za-z_.])[\w./~$-]*\.[A-Za-z0-9]{1,6}"
    r"|~/\.[\w./-]+"
    r"|\.(?:env|npmrc|netrc|ssh|aws|kube|docker)(?:/[\w./-]+)?)"
)

CRED_NAME = re.compile(
    r'"?([A-Z][A-Z0-9_]{2,40}_(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|CREDENTIALS))"?'
)


def fenced_blocks(text):
    """Executable regions of a SKILL.md, as raw strings.

    Odd-indexed segments of a ```-split are fence bodies. The language tag,
    when present, is the first token of the body because the newline that
    separated it is gone.
    """
    out = []
    parts = text.split("```")
    for i in range(1, len(parts), 2):
        body = parts[i].strip()
        if not body:
            continue
        first, _, rest = body.partition(" ")
        lang = first.lower()
        if lang in SHELL_LANGS:
            body = rest.strip()
        elif lang and not COMMAND_START.match(body):
            # A tagged non-shell fence (json, python, yaml...) that does not
            # open like a shell command.
            continue
        if body and COMMAND_START.search(body):
            out.append(body[:2000])
    return out


def referenced_paths(text, cap=30):
    out, seen = [], set()
    for m in PATH_LIKE.finditer(text):
        p = m.group(1).rstrip(".,;:)`\"'")
        if len(p) < 4 or len(p) > 200 or p in seen:
            continue
        seen.add(p)
        out.append(p)
        if len(out) >= cap:
            break
    return out


def declared_credentials(text, cap=20):
    """Credential-shaped names a skill declares it needs.

    A skill listing OPENAI_API_KEY in its metadata is stating it will hold
    a live credential. That is a capability claim with real consequence,
    and it is the one piece of frontmatter worth reading as an action.
    """
    out, seen = [], set()
    for m in CRED_NAME.finditer(text):
        name = m.group(1)
        if name in seen:
            continue
        seen.add(name)
        out.append(name)
        if len(out) >= cap:
            break
    return out

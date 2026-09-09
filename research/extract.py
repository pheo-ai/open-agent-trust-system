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

# What separates a fence's language tag from its body. Real whitespace in an
# authored document; the space it was collapsed into in most of this corpus;
# and, in the 4.4% of rows the sanitizer escaped rather than collapsed, the
# two literal characters backslash-n.
SEP = re.compile(r"(?:\s|\\[nrt])+")


def _strip_leading_sep(s):
    m = SEP.match(s)
    return s[m.end():] if m else s


def fenced_blocks(text, stats=None):
    """Executable regions of a SKILL.md, as raw strings.

    Odd-indexed segments of a ```-split are fence bodies. Whether a fence
    carried a language tag survives sanitization in one place only: the
    character that followed the opening ```. In the authored document that
    is a newline for an untagged fence and a tag for a tagged one, and the
    sanitizer turned the newline into a space. So a body whose raw form
    opens with whitespace had no tag, and one that does not opens with its
    tag. This holds for authored markdown too, where the newline survives
    as itself.

    Testing the tag-prefixed body against COMMAND_START, as an earlier
    version did, admits every ```python, ```go, ```docker, ```node,
    ```make, ```cargo, ```npm, ```git and ```jq fence, because those tags
    are themselves command names. Those bodies were then handed to a
    resolver written for shell. See the seventh defect in the paper.

    Pass a dict as `stats` to collect what was skipped and truncated;
    counts are added to the keys `tagged_nonshell`, `truncated`, `blocks`.
    """
    out = []
    parts = text.split("```")
    for i in range(1, len(parts), 2):
        raw = parts[i]
        body = raw.strip()
        if not body:
            continue
        if SEP.match(raw):
            # No tag survived, so the body is content. Require it to open
            # like a command: bare fences also carry sample output, JSON,
            # and file listings.
            body = _strip_leading_sep(body)
            if not COMMAND_START.match(body):
                continue
        else:
            head = SEP.split(body, 1)
            first, rest = head[0], (head[1] if len(head) > 1 else "")
            if first.lower() not in SHELL_LANGS:
                # A fence in some other language. Whatever its tag spells,
                # its content is not a shell command string.
                if stats is not None:
                    stats["tagged_nonshell"] = stats.get("tagged_nonshell", 0) + 1
                continue
            body = rest.strip()
        if not body or not COMMAND_START.search(body):
            continue
        if stats is not None:
            stats["blocks"] = stats.get("blocks", 0) + 1
            if len(body) > 2000:
                stats["truncated"] = stats.get("truncated", 0) + 1
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

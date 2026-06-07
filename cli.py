"""
cli.py — Click CLI entrypoint for the timecapsule tool.

Commands:
  capsule write   — Encrypt and store a new time capsule
  capsule list    — Show all capsules in a Rich table (content hidden)
  capsule open    — Decrypt a capsule (or show countdown if locked)
  capsule export  — Export all capsules as a zip backup
  capsule stats   — Show mood bar chart and stats
  capsule init    — Initialize optional Git sync
"""

from __future__ import annotations

import io
import json
import os
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import os as _os
# Force UTF-8 output encoding on Windows (CP1252 cannot render emoji/box-drawing chars)
_os.environ.setdefault("PYTHONUTF8", "1")

import click
from rich import box
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text

from capsule import CapsuleLockedError, CapsuleNotFoundError, CorruptedCapsuleError, TamperedCapsuleError
from capsule.encrypt import decrypt, encrypt, format_countdown
from capsule.git_sync import auto_commit, init_git
from capsule.storage import (
    CAPSULES_DIR,
    TIMECAPSULE_DIR,
    create_capsule,
    get_index_entry,
    load_capsule,
    load_index,
    refresh_unlock_statuses,
    update_index_entry,
)
from capsule.timestamp import request_timestamp, verify_timestamp

# Use a console that handles Unicode safely on Windows
console = Console(highlight=False)

# ---------------------------------------------------------------------------
# Mood emoji map
# ---------------------------------------------------------------------------

MOOD_EMOJI = {
    "hopeful": "🌱",
    "happy": "😊",
    "excited": "🚀",
    "anxious": "😰",
    "nostalgic": "🕰️",
    "melancholic": "🌧️",
    "proud": "🏆",
    "grateful": "🙏",
    "uncertain": "🤔",
    "determined": "💪",
    "peaceful": "☮️",
    "sad": "😢",
}

MOOD_COLORS = {
    "hopeful": "green",
    "happy": "yellow",
    "excited": "bright_magenta",
    "anxious": "red",
    "nostalgic": "blue",
    "melancholic": "blue",
    "proud": "gold1",
    "grateful": "cyan",
    "uncertain": "grey70",
    "determined": "orange3",
    "peaceful": "aquamarine3",
    "sad": "steel_blue",
}


def mood_display(mood: str) -> str:
    emoji = MOOD_EMOJI.get(mood.lower(), "✨")
    return f"{emoji} {mood}"


# ---------------------------------------------------------------------------
# CLI Group
# ---------------------------------------------------------------------------

@click.group()
@click.version_option(version="1.0.0", prog_name="timecapsule")
def cli():
    """
    \b
    ╔════════════════════════════════════════╗
    ║   🕰️  Personal Time Capsule CLI        ║
    ║   Write letters to your future self.  ║
    ║   Cryptographically sealed.           ║
    ╚════════════════════════════════════════╝

    Encrypt messages that only unlock after a set date.
    """
    # Refresh unlock statuses on every command
    try:
        refresh_unlock_statuses()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# write
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("message", required=False)
@click.option("--unlock", "-u", required=True, help="Unlock date in YYYY-MM-DD format (e.g. 2027-06-01)")
@click.option("--tag", "-t", "tags", multiple=True, help="Category tags (can be repeated)")
@click.option("--mood", "-m", default="hopeful", show_default=True,
              help="Your mood right now (hopeful, happy, excited, anxious, nostalgic, ...)")
@click.option("--git/--no-git", default=True, help="Auto-commit to configured git remote")
def write(message: str | None, unlock: str, tags: tuple, mood: str, git: bool):
    """Write a new encrypted time capsule message.

    \b
    Examples:
      capsule write "Hello future me!" --unlock 2027-06-01 --tag career --mood hopeful
      capsule write --unlock 2030-01-01  (opens $EDITOR for longer messages)
    """
    # Validate unlock date
    try:
        unlock_dt = datetime.strptime(unlock, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        console.print("[bold red]✗[/bold red] Invalid date format. Use YYYY-MM-DD (e.g. 2027-06-01)")
        sys.exit(1)

    if unlock_dt <= datetime.now(timezone.utc):
        console.print("[bold yellow]⚠[/bold yellow]  Unlock date is in the past — this capsule will be immediately openable.")

    # Get message (editor if not provided inline)
    if not message:
        TEMPLATE = "\n\n# Write your message above this line.\n# Lines starting with # are ignored.\n"
        raw = click.edit(TEMPLATE)
        if raw is None:
            console.print("[bold red]✗[/bold red] No message entered. Capsule not created.")
            sys.exit(1)
        message = "\n".join(
            line for line in raw.splitlines()
            if not line.startswith("#")
        ).strip()

    if not message:
        console.print("[bold red]✗[/bold red] Empty message. Capsule not created.")
        sys.exit(1)

    tags_list = list(tags)

    console.print()
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("🔐 Encrypting your message...", total=None)

        # Encrypt
        try:
            encrypted = encrypt(message, mood, tags_list, unlock_dt)
        except Exception as exc:
            console.print(f"[bold red]✗[/bold red] Encryption failed: {exc}")
            sys.exit(1)

        progress.update(task, description="🕰️  Requesting trusted timestamp...")

        # RFC 3161 timestamp
        blob_bytes = json.dumps(encrypted, sort_keys=True).encode("utf-8")
        rfc3161_token = request_timestamp(blob_bytes)
        timestamp_ok = rfc3161_token is not None
        rfc3161_token_hex = rfc3161_token.hex() if rfc3161_token else None

        progress.update(task, description="💾 Saving capsule...")

        # Save
        capsule_id = create_capsule(
            message=message,
            mood=mood,
            tags=tags_list,
            unlock_date=unlock,
            encrypted_payload=encrypted,
            rfc3161_token_hex=rfc3161_token_hex,
            timestamp_verified=timestamp_ok,
        )

        # Optional git commit
        if git:
            progress.update(task, description="📦 Committing to git...")
            auto_commit(capsule_id, unlock)

    # Success panel
    tag_str = " ".join(f"[cyan]#{t}[/cyan]" for t in tags_list) if tags_list else "[dim]none[/dim]"
    mood_str = mood_display(mood)

    panel_content = (
        f"[bold]ID:[/bold]      [dim]{capsule_id}[/dim]\n"
        f"[bold]Unlocks:[/bold] [yellow]{unlock}[/yellow]\n"
        f"[bold]Mood:[/bold]    {mood_str}\n"
        f"[bold]Tags:[/bold]    {tag_str}\n"
    )
    if not timestamp_ok:
        panel_content += "\n[yellow]⚠[/yellow]  Trusted timestamp unavailable (no internet) — saved locally."

    console.print(
        Panel(
            panel_content,
            title="[bold green]✓ Capsule Sealed[/bold green]",
            border_style="green",
            padding=(1, 2),
        )
    )
    console.print(f"\n[dim]Opens in:[/dim] [bold cyan]{format_countdown(unlock + 'T00:00:00+00:00')}[/bold cyan]\n")


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------

@cli.command("list")
def list_capsules():
    """List all capsules — content hidden, metadata only."""
    entries = load_index()

    if not entries:
        console.print(
            Panel(
                "[dim]No capsules yet. Write your first one with:[/dim]\n\n"
                "  [bold cyan]capsule write \"Hello future me!\" --unlock 2027-01-01[/bold cyan]",
                title="🕰️  Time Capsule Vault",
                border_style="blue",
                padding=(1, 2),
            )
        )
        return

    # Sort by unlock date
    entries_sorted = sorted(entries, key=lambda e: e.get("unlock_date", ""))

    table = Table(
        title="🕰️  Time Capsule Vault",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold bright_white",
        border_style="bright_blue",
        padding=(0, 1),
        expand=False,
    )

    table.add_column("#", style="dim", width=3, justify="right")
    table.add_column("ID", style="dim cyan", width=8)
    table.add_column("Hint", style="white", min_width=24)
    table.add_column("Unlock Date", justify="center", width=12)
    table.add_column("Mood", width=16)
    table.add_column("Tags", width=20)
    table.add_column("Status", justify="center", width=12)
    table.add_column("Timestamp", justify="center", width=10)

    locked_count = 0
    unlocked_count = 0

    for i, entry in enumerate(entries_sorted, 1):
        is_unlocked = entry.get("is_unlocked", False)
        ts_ok = entry.get("timestamp_verified", False)

        if is_unlocked:
            status = Text("🔓 OPEN", style="bold green")
            row_style = "green"
            unlocked_count += 1
        else:
            status = Text("🔒 LOCKED", style="bold red")
            row_style = ""
            locked_count += 1

        short_id = entry["id"][:8]
        mood = entry.get("mood", "")
        mood_col = Text(mood_display(mood), style=MOOD_COLORS.get(mood.lower(), "white"))
        tags = entry.get("tags", [])
        tag_col = " ".join(f"#{t}" for t in tags) if tags else "—"
        ts_col = Text("✓", style="green") if ts_ok else Text("—", style="dim")

        unlock_date = entry.get("unlock_date", "—")

        table.add_row(
            str(i),
            short_id,
            entry.get("title_hint", "..."),
            unlock_date,
            mood_col,
            tag_col,
            status,
            ts_col,
            style=row_style if is_unlocked else "",
        )

    console.print()
    console.print(table)
    console.print(
        f"\n  [bold green]🔓 {unlocked_count} unlocked[/bold green]  "
        f"[bold red]🔒 {locked_count} locked[/bold red]  "
        f"[dim]Total: {len(entries)}[/dim]\n"
    )


# ---------------------------------------------------------------------------
# open
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("capsule_id")
@click.option("--skip-verify/--verify", default=False, help="Skip RFC 3161 timestamp verification")
def open(capsule_id: str, skip_verify: bool):
    """Open and decrypt a capsule by its ID (or first 8 chars of ID)."""

    # Support short ID prefix matching
    entries = load_index()
    matched = [e for e in entries if e["id"].startswith(capsule_id)]

    if not matched:
        console.print(f"[bold red]✗[/bold red] No capsule found matching ID: [cyan]{capsule_id}[/cyan]")
        sys.exit(1)
    if len(matched) > 1:
        console.print(f"[bold yellow]⚠[/bold yellow]  Multiple capsules match '[cyan]{capsule_id}[/cyan]'. Please provide more characters.")
        sys.exit(1)

    entry = matched[0]
    full_id = entry["id"]

    # Load .capsule file
    try:
        capsule_data = load_capsule(full_id)
    except CapsuleNotFoundError as exc:
        console.print(f"[bold red]✗[/bold red] {exc}")
        sys.exit(1)

    # RFC 3161 verification
    if not skip_verify and capsule_data.get("rfc3161_token_hex"):
        try:
            blob_bytes = json.dumps(
                {k: v for k, v in capsule_data.items()
                 if k not in ("rfc3161_token_hex", "timestamp_verified", "created_at")},
                sort_keys=True,
            ).encode("utf-8")
            verify_timestamp(bytes.fromhex(capsule_data["rfc3161_token_hex"]), blob_bytes)
        except TamperedCapsuleError as exc:
            console.print(f"[bold red]⚠  TAMPERING DETECTED[/bold red]\n[red]{exc}[/red]")
            sys.exit(1)

    # Decrypt
    try:
        payload = decrypt(capsule_data)
    except CapsuleLockedError as exc:
        unlock_date = entry.get("unlock_date", "")
        countdown = format_countdown(f"{unlock_date}T00:00:00+00:00")

        console.print()
        console.print(
            Panel(
                f"[bold red]🔒 This capsule is still sealed.[/bold red]\n\n"
                f"[dim]Unlocks on:[/dim] [yellow bold]{unlock_date}[/yellow bold]\n"
                f"[dim]Opens in:[/dim]   [cyan bold]{countdown}[/cyan bold]\n\n"
                f"[dim italic]Come back later — some things are worth the wait.[/dim italic]",
                title="[red]⛔ Access Denied[/red]",
                border_style="red",
                padding=(1, 2),
            )
        )
        console.print()
        sys.exit(0)

    except CorruptedCapsuleError as exc:
        console.print(f"[bold red]✗ CORRUPTED:[/bold red] {exc}")
        sys.exit(1)

    # Mark as unlocked in index
    update_index_entry(full_id, {"is_unlocked": True})

    # Display the decrypted capsule
    mood = payload.get("mood", "")
    tags = payload.get("tags", [])
    created_at = capsule_data.get("created_at", entry.get("created_at", ""))
    unlock_ts = payload.get("unlock_timestamp", "")
    message = payload.get("message", "")

    # Format created_at nicely
    try:
        created_dt = datetime.fromisoformat(created_at)
        created_str = created_dt.strftime("%B %d, %Y at %H:%M UTC")
    except (ValueError, TypeError):
        created_str = created_at

    tag_str = " ".join(f"[cyan]#{t}[/cyan]" for t in tags) if tags else "[dim]none[/dim]"
    ts_note = "[green]✓ Timestamp verified[/green]" if capsule_data.get("timestamp_verified") else "[yellow]⚠ No trusted timestamp[/yellow]"

    header = (
        f"[dim]Written:[/dim]  [white]{created_str}[/white]\n"
        f"[dim]Mood:[/dim]     {mood_display(mood)}\n"
        f"[dim]Tags:[/dim]     {tag_str}\n"
        f"[dim]Verify:[/dim]   {ts_note}\n"
    )

    console.print()
    console.print(
        Panel(
            header,
            title=f"[bold green]🔓 Capsule Opened — {full_id[:8]}[/bold green]",
            border_style="green",
            padding=(0, 2),
        )
    )
    console.print(
        Panel(
            f"\n{message}\n",
            title="[bold white]📖 Your Message[/bold white]",
            border_style="bright_blue",
            padding=(1, 3),
        )
    )
    console.print()


# ---------------------------------------------------------------------------
# export
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--output", "-o", default="~/timecapsule-backup.zip",
              show_default=True, help="Output zip file path")
def export(output: str):
    """Export all capsules as an encrypted backup zip."""
    import capsule.storage as _storage

    output_path = Path(output).expanduser().resolve()

    entries = load_index()
    if not entries:
        console.print("[yellow]⚠[/yellow]  No capsules to export.")
        return

    capsule_files = list(_storage.CAPSULES_DIR.glob("*.capsule"))
    index_file = _storage.TIMECAPSULE_DIR / "index.json"

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task(f"📦 Exporting {len(capsule_files)} capsule(s)...", total=None)

        with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for cf in capsule_files:
                zf.write(cf, arcname=f"capsules/{cf.name}")
            if index_file.exists():
                zf.write(index_file, arcname="index.json")

    size_kb = output_path.stat().st_size / 1024
    console.print(
        Panel(
            f"[bold]Output:[/bold]   [cyan]{output_path}[/cyan]\n"
            f"[bold]Capsules:[/bold] {len(capsule_files)}\n"
            f"[bold]Size:[/bold]     {size_kb:.1f} KB\n\n"
            "[dim]Note: The backup contains encrypted capsule files.\n"
            "You'll need your master.key to decrypt them.[/dim]",
            title="[bold green]✓ Export Complete[/bold green]",
            border_style="green",
            padding=(1, 2),
        )
    )


# ---------------------------------------------------------------------------
# stats
# ---------------------------------------------------------------------------

@cli.command()
def stats():
    """Show capsule statistics and mood breakdown."""
    entries = load_index()

    if not entries:
        console.print("[dim]No capsules yet.[/dim]")
        return

    total = len(entries)
    locked = sum(1 for e in entries if not e.get("is_unlocked"))
    unlocked = total - locked
    ts_verified = sum(1 for e in entries if e.get("timestamp_verified"))

    # Mood counts
    from collections import Counter
    mood_counts: Counter = Counter()
    for entry in entries:
        mood = entry.get("mood", "unknown").lower()
        mood_counts[mood] += 1

    # Timeline: capsules by year
    from collections import defaultdict
    by_year: dict[str, int] = defaultdict(int)
    for entry in entries:
        try:
            year = datetime.fromisoformat(entry["created_at"]).strftime("%Y")
            by_year[year] += 1
        except (KeyError, ValueError):
            pass

    console.print()

    # Summary panel
    console.print(
        Panel(
            f"  [bold]Total Capsules:[/bold]     [white]{total}[/white]\n"
            f"  [bold]🔒 Locked:[/bold]          [red]{locked}[/red]\n"
            f"  [bold]🔓 Unlocked:[/bold]        [green]{unlocked}[/green]\n"
            f"  [bold]🕰️  Timestamped:[/bold]     [cyan]{ts_verified}[/cyan]\n",
            title="[bold bright_white]📊 Capsule Statistics[/bold bright_white]",
            border_style="bright_blue",
            padding=(0, 2),
        )
    )

    # Mood bar chart
    if mood_counts:
        console.print()
        console.print("[bold bright_white]  🎭 Mood Breakdown[/bold bright_white]\n")

        max_count = max(mood_counts.values())
        bar_width = 30

        for mood, count in mood_counts.most_common():
            emoji = MOOD_EMOJI.get(mood, "✨")
            color = MOOD_COLORS.get(mood, "white")
            bar_len = int((count / max_count) * bar_width)
            bar = "█" * bar_len + "░" * (bar_width - bar_len)
            label = f"{emoji} {mood:<14}"
            console.print(
                f"  {label} [bold {color}]{bar}[/bold {color}]  [dim]{count}[/dim]"
            )

    # Year breakdown
    if by_year:
        console.print()
        console.print("[bold bright_white]  📅 Capsules by Year[/bold bright_white]\n")
        max_year_count = max(by_year.values())
        for year in sorted(by_year):
            count = by_year[year]
            bar_len = int((count / max_year_count) * 20)
            bar = "▓" * bar_len
            console.print(f"  {year}  [cyan]{bar}[/cyan]  [dim]{count}[/dim]")

    # Upcoming unlocks
    future = sorted(
        [e for e in entries if not e.get("is_unlocked")],
        key=lambda e: e.get("unlock_date", ""),
    )
    if future:
        console.print()
        console.print("[bold bright_white]  ⏳ Next Unlocks[/bold bright_white]\n")
        for e in future[:3]:
            countdown = format_countdown(f"{e['unlock_date']}T00:00:00+00:00")
            console.print(
                f"  [dim]{e['id'][:8]}[/dim]  [yellow]{e['unlock_date']}[/yellow]  "
                f"[dim]in {countdown}[/dim]  {mood_display(e.get('mood', ''))}"
            )

    console.print()


# ---------------------------------------------------------------------------
# init
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--git", "git_url", default=None, help="Remote git repository URL for auto-sync")
def init(git_url: str | None):
    """Initialize timecapsule settings (optional git remote)."""
    from capsule.encrypt import get_master_key, MASTER_KEY_PATH

    # Ensure master key exists
    get_master_key()

    console.print(
        Panel(
            f"[bold]Vault:[/bold]       [cyan]{TIMECAPSULE_DIR}[/cyan]\n"
            f"[bold]Master Key:[/bold]  [cyan]{MASTER_KEY_PATH}[/cyan] [dim](keep this safe!)[/dim]\n",
            title="[bold green]✓ timecapsule initialized[/bold green]",
            border_style="green",
            padding=(1, 2),
        )
    )

    if git_url:
        console.print(f"[dim]Setting up git remote:[/dim] {git_url}")
        success = init_git(git_url)
        if success:
            console.print(f"[bold green]✓[/bold green] Git remote configured: [cyan]{git_url}[/cyan]")
            console.print("[dim]  master.key will never be committed (protected by .gitignore)[/dim]")
        else:
            console.print("[bold red]✗[/bold red] Git setup failed. Check the URL and try again.")

    console.print(
        "\n[dim]Get started:[/dim]\n"
        "  [bold cyan]capsule write \"Hello future me!\" --unlock 2027-01-01[/bold cyan]\n"
    )


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    try:
        cli()
    except KeyboardInterrupt:
        console.print("\n[dim]Interrupted.[/dim]")
        sys.exit(0)
    except Exception as exc:
        console.print(f"\n[bold red]Unexpected error:[/bold red] {exc}")
        sys.exit(1)

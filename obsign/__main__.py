import pathlib
import subprocess

import click
import rich
from rich.console import Console

console = Console(highlight=False)


@click.group()
@click.option(
    "--signatures-dir",
    type=click.Path(
        path_type=pathlib.Path,
        file_okay=False,
        dir_okay=True,
        exists=True,
        readable=True,
        writable=True,
        resolve_path=True,
    ),
    envvar="OBSIDIAN_SIGS_DIR",
)
@click.pass_context
def cli(ctx, signatures_dir):
    ctx.obj["SIGS_DIR"] = signatures_dir
    ctx.obj["OB_DIR"] = signatures_dir.parent


@click.command()
@click.argument(
    "file",
    type=click.Path(
        path_type=pathlib.Path,
        file_okay=True,
        dir_okay=False,
        readable=True,
        exists=True,
        resolve_path=True,
    ),
)
@click.pass_context
def sign(ctx, file):
    ob_dir = ctx.obj["OB_DIR"]
    console.print(f"Signing file [cyan]{file.relative_to(ob_dir)}[/]")

    if file.suffix in [".md", ".txt", ".rst"]:
        console.print("Text file detected, so signing with [yellow]clearsign[/].")

        # Get signature filename by incrementing version if previous versions exist
        sig_number = 0
        for prev_versions in ctx.obj["SIGS_DIR"].glob(f"{file.name}.*.asc"):
            if (num := int(prev_versions.name[-7:-4]) + 1) > sig_number:
                sig_number = num
        output_file = ctx.obj["SIGS_DIR"] / (file.name + f".{sig_number:03}.asc")

        # Sign the file
        subprocess.run(
            ["gpg", "--output", output_file, "--clearsign", file], check=True
        )
        console.print(
            f"Created signed file [magenta]{output_file.relative_to(ob_dir)}[/]"
        )

        # Verify the newly-created signature to allow the user to see the key and timestamp
        verify_result = subprocess.run(
            ["gpg", "--verify", output_file], check=True, capture_output=True, text=True
        )
        if "Good signature" in verify_result.stderr:
            console.print("[green]" + verify_result.stderr + "[/]")
        else:
            console.print("[red]" + verify_result.stderr + "[/]")
            return

        console.print()

        # Create timestamp query file
        tsq_file = output_file.parent / (output_file.name + ".apple.tsq")
        subprocess.run(
            [
                "openssl",
                "ts",
                "-query",
                "-data",
                file,
                "-no_nonce",
                "-sha512",
                "-cert",
                "-out",
                tsq_file,
            ],
            check=True,
        )
        console.print(
            f"Created timestamp query file [yellow]{tsq_file.relative_to(ob_dir)}[/]"
        )

        # Send to server
        tsr_file = output_file.parent / (output_file.name + ".apple.tsr")
        with open(tsr_file, "w") as tsr_file_w:
            subprocess.run(
                [
                    "curl",
                    "--silent",
                    "-H",
                    "Content-Type: application/timestamp-query",
                    "--data-binary",
                    f"@{tsq_file}",
                    "http://timestamp.apple.com/ts01",
                    "--output",
                    tsr_file,
                ],
                check=True,
            )

        assert tsr_file.exists()
        console.print(
            f"Received timestamp response [magenta]{tsr_file.relative_to(ob_dir)}[/]"
        )

        verify_timestamp_result = subprocess.run(
            [
                "openssl",
                "ts",
                "-verify",
                "-in",
                tsr_file,
                "-queryfile",
                tsq_file,
                "-CAfile",
                ctx.obj["SIGS_DIR"] / "AppleIncRootCertificate.pem",
                "-untrusted",
                ctx.obj["SIGS_DIR"] / "AppleTimestampCA.cer",
            ],
            capture_output=True,
            text=True,
        )
        if verify_timestamp_result.returncode == 0:
            console.print("[green]openssl ts: " + verify_timestamp_result.stdout)
        else:
            console.print("[red]" + verify_timestamp_result.stdout)
            console.print("[red]" + verify_timestamp_result.stderr)

    else:
        raise NotImplementedError


cli.add_command(sign)

if __name__ == "__main__":
    cli(obj={})

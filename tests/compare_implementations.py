from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = (
    "safe Schnorr transcript",
    "public key added after the first challenge",
    "cross-transcript interaction",
    "earlier data with a later challenge",
    "interaction with an untracked operand",
    "incomplete Bulletproof transcript",
)
EXPECTED_PYTHON = ("accepted", "detected", "detected", "detected", "detected", "detected")
EXPECTED_RUST = ("accepted", "detected", "detected", "accepted", "detected", "detected")


def run(command: list[str]) -> str:
    result = subprocess.run(
        command,
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True
    )
    return result.stdout


def split_scenarios(output: str) -> list[str]:
    return [part.strip() for part in output.split("----------------") if part.strip()]


def classify(output: str) -> str:
    if "No Fiat-Shamir heuristic vulnerability detected." in output:
        return "accepted"
    if "Detected:" in output or "Detection:" in output:
        return "detected"
    raise RuntimeError(f"unknown scenario result:\n{output}")


def main() -> None:
    virtualenv_python = ROOT / "venv" / "bin" / "python"
    python = str(virtualenv_python) if virtualenv_python.exists() else sys.executable

    python_results = split_scenarios(
        run([python, "python_proto/weak_shnorr.py"])
    )
    python_results.extend(split_scenarios(
        run([python, "python_proto/weak_bulletproofs.py"])
    ))
    rust_results = split_scenarios(run(["cargo", "run", "--quiet"]))

    if len(python_results) != len(SCENARIOS):
        raise RuntimeError(
            f"expected {len(SCENARIOS)} Python scenarios, got {len(python_results)}"
        )
    if len(rust_results) != len(SCENARIOS):
        raise RuntimeError(
            f"expected {len(SCENARIOS)} Rust scenarios, got {len(rust_results)}"
        )

    python_statuses = tuple(map(classify, python_results))
    rust_statuses = tuple(map(classify, rust_results))
    if python_statuses != EXPECTED_PYTHON:
        raise RuntimeError(f"unexpected Python results: {python_statuses}")
    if rust_statuses != EXPECTED_RUST:
        raise RuntimeError(f"unexpected Rust results: {rust_statuses}")

    print("scenario | Python | Rust")
    print("--- | --- | ---")
    for scenario, python_status, rust_status in zip(
        SCENARIOS,
        python_statuses,
        rust_statuses
    ):
        print(f"{scenario} | {python_status} | {rust_status}")
    print("\nintentional difference: Rust no longer treats a later challenge "
          "with earlier data as a vulnerability by itself")
    print("accepted means no finding, not a proof of protocol security")


if __name__ == "__main__":
    main()

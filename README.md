# FortiGate-SyntaxChecker

Python script to check the CLI syntax of a FortiGate backup file.

## Installation

1. Clone this repository or download the files to your local machine.
2. Make sure you have Python 3.7 or newer installed.
3. Install the required package using pip:

    ```sh
    pip install -r requirements.txt
    ```

## Usage

Run the syntax checker on a FortiGate CLI script file:

```sh
python syntax-checker.py path/to/cli_script.txt
```

To include warnings in the output, use:

```sh
python syntax-checker.py path/to/cli_script.txt --warnings
```

## Output

The script will print a table of potential issues found in the CLI script, including line numbers, severity, and details.

![alt text](CLI-output.png)

## Notes

- This tool uses heuristic checks and is not an authoritative parser for FortiGate CLI.
- It is intended to help catch common mistakes and formatting issues before uploading or restoring configurations.

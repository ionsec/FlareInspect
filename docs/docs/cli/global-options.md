# Global CLI Options

These options apply to all FlareInspect commands and are set before the command name.

| Option | Description |
|--------|-------------|
| `-v, --version` | Print the FlareInspect version and exit |
| `-q, --quiet` | Suppress the banner and all non-essential output |
| `--no-banner` | Skip the startup banner (output is otherwise normal) |
| `--debug` | Enable debug-level logging for troubleshooting |

## Examples

### Print Version

```bash
flareinspect --version
```

### Quiet Mode (CI-Friendly Output)

```bash
flareinspect -q assess --token $CLOUDFLARE_TOKEN
```

### Debug Mode

```bash
flareinspect --debug assess --token $CLOUDFLARE_TOKEN
```

Debug mode sets `CLOUDFLARE_DEBUG=true` and increases log verbosity, which is useful for diagnosing API connectivity or permission issues.

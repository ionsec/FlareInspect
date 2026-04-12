# Plugins

FlareInspect supports local plugins for extending security checks and hooks.

## Plugin Loader

The plugin loader scans the `./plugins/` directory for subdirectories
containing a `flareinspect-plugin.json` manifest file.

### Directory Structure

```
plugins/
  my-plugin/
    flareinspect-plugin.json
    index.js
```

### Manifest Schema

```json
{
  "name": "my-plugin",
  "version": "1.0.0",
  "description": "Custom security checks",
  "author": "Your Name",
  "main": "index.js",
  "checks": [],
  "hooks": {}
}
```

## Security Model

!!! warning "Trusted Code Boundary"
    Plugins execute as local code with the same privileges as FlareInspect.
    They are **not** sandboxed. Only install plugins from trusted sources.

## Plugin API

The `FlareInspectPlugin` base class provides:

| Method | Description |
|--------|-------------|
| `preAssess(assessment)` | Called before assessment starts |
| `postAssess(assessment)` | Called after assessment completes |
| `getChecks()` | Returns additional check definitions |

## Loaded Plugins

To view loaded plugins, check the application logs at startup:

```
[info] Loaded plugin: my-plugin v1.0.0
```

## See Also

- [Writing Plugins](writing-plugins.md)

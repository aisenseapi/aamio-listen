# aamio-listen

Renamed to [`aamio`](https://pypi.org/project/aamio/).

This package installs `aamio` and re-exports it, so `import aamio_listen` keeps
working. New code should use `aamio`:

```bash
pip install aamio
```

The command line is the same either way: installing `aamio` gives you both the
`aamio` and the `aamio-listen` commands.

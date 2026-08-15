# vock selftest ({{ARCH}})

| Test | Verdict | Checks | Full log |
|------|---------|--------|----------|
{{RESULT_ROWS}}

Every row's full log is uploaded as its own artifact; the download link
points at exactly that test's output.

## Reproduce by hand

The same commands `vock selftest --help` prints (run from the kernel source
tree; each test first configures + builds the kernel via
`vng --force --configitem ... --build`; `vock` is whichever binary you run,
`./vock.bin` in a build tree works too):

{{RAW_COMMANDS}}

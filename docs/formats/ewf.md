# E01 / EWF

Latent does not reimplement the Expert Witness Compression Format. It binds
[libewf](https://github.com/libyal/libewf) and exposes the acquired media as one
logical source, so E01 images (single or multi-segment) read the same as a flat
image through the rest of the tool.

## Optional dependency

libewf is an optional system dependency. If the build script finds it, the E01
backend is compiled in; if not, the crate still builds and opening an E01 returns
a clear "built without libewf" error. Nothing else changes.

The backend is Unix (Linux and macOS) for now; on Windows the crate builds
against the stub.

- Debian / Ubuntu: `apt-get install libewf-dev`
- macOS: `brew install libewf`
- Runtime-only installs (a `libewf.so.N` with no `-dev` symlink) are handled too:
  the build script symlinks it where the linker can find it.

Point the build at a non-standard location with `LIBEWF_LIB_DIR=/path/to/lib`,
or force the backend off with `LATENT_EWF=0`.

## What the backend does

- Opens strictly read-only (libewf access flag read; no write path exists).
- Presents `libewf_handle_get_media_size` as the source size and serves positioned
  reads with `libewf_handle_read_random`, one call at a time under a mutex.
- Surfaces the acquisition MD5 and SHA-1 when the image stored them, so they can
  back a native EWF integrity check.

## Test fixtures

`latent-source/tests/fixtures/ewf/` holds a small single-segment and a
multi-segment image. They were written once, out of tree, with the committed
`generate.rs`, so no write path ever lands in the crate itself.

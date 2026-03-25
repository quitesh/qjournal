# qjournal

Cross-platform, native Rust implementation of the
[systemd-journald](https://www.freedesktop.org/software/systemd/man/systemd-journald.service.html)
binary journal format.

Read and write `.journal` files fully compatible with
`journalctl --file=<path>`, without depending on `libsystemd`.

> [!NOTE]
> This package has been largely AI-generated. I intend to review it thoroughly in the future,
> but any help reviewing or contributing is appreciated!

## Features

- **Write** journal entries with arbitrary fields
- **Read** entries back, iterate, or query by field value
- Zstd compression support (enabled by default)
- Compatible with keyed-hash and compact journal formats
- No C dependencies — pure Rust with safe memory-mapped I/O

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
qjournal = "0.1"
```

### Writing

```rust
use qjournal::JournalWriter;
use std::path::Path;

let mut writer = JournalWriter::open(Path::new("/tmp/test.journal"))?;
writer.append_entry(&[
    ("MESSAGE", b"Hello, world!" as &[u8]),
    ("PRIORITY", b"6"),
    ("SYSLOG_IDENTIFIER", b"myapp"),
])?;
writer.flush()?;
```

### Reading

```rust
use qjournal::JournalReader;
use std::path::Path;

let reader = JournalReader::open(Path::new("/tmp/test.journal"))?;
for entry in reader.entries() {
    let entry = entry?;
    if let Some(msg) = entry.get(b"MESSAGE") {
        println!("{}", String::from_utf8_lossy(msg));
    }
}
```

### Querying by field

```rust
let errors = reader.entries_for_field("PRIORITY", b"3")?;
for e in &errors {
    println!("{:?}", e.message());
}
```

Verify output with systemd tooling:

```sh
journalctl --file=/tmp/test.journal
```

## Feature flags

| Flag               | Default | Description              |
|--------------------|---------|--------------------------|
| `zstd-compression` | yes     | Enable zstd compression  |

## License

Licensed under the [GNU Lesser General Public License v2.1 or later](LICENSE).

SPDX-License-Identifier: `LGPL-2.1-or-later`

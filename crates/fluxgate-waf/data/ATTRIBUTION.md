# Attribution

The file [`fingerprints.txt`](./fingerprints.txt) in this directory, the SQLi
tokenizer / folding / fingerprint logic in
[`../src/sqli/libinjection/`](../src/sqli/libinjection/), and the XSS engine +
HTML5 tokenizer in [`../src/xss/libinjection/`](../src/xss/libinjection/), are
**derived from [libinjection](https://github.com/libinjection/libinjection)** by
Nick Galbreath and the libinjection contributors.

`fingerprints.txt` is copied verbatim from libinjection's
`src/fingerprints.txt`. The Rust port of the SQLi engine and its keyword table is
a mechanical translation of libinjection's `src/libinjection_sqli.c` and
`src/libinjection_sqli_data.h`. The Rust port of the XSS engine, the HTML5
tokenizer, and the tag/attribute/event blacklists is a mechanical translation of
libinjection's `src/libinjection_xss.c` and `src/libinjection_html5.c` (the
blacklist tables in `../src/xss/libinjection/blacklists.rs` are generated
directly from the `BLACKTAG` / `BLACKATTR` / `BLACKATTREVENT` arrays in
`libinjection_xss.c`).

Additionally, the **unmodified C sources** `libinjection_sqli.c`,
`libinjection_sqli.h`, `libinjection_sqli_data.h`, `libinjection_xss.c`,
`libinjection_xss.h`, `libinjection_html5.c`, `libinjection_html5.h`,
`libinjection.h`, and `libinjection_error.h` are vendored under
[`../../fluxgate-waf-difftest/vendor/libinjection/`](../../fluxgate-waf-difftest/vendor/libinjection/).
They are compiled (dev/test only) as the ground-truth oracle for the differential
tests that guard the Rust ports against drift. Same BSD-3-Clause license, below.

libinjection is distributed under the **BSD 3-Clause License**, reproduced in
full below.

## libinjection License (BSD-3-Clause)

```
Copyright (c) 2012-2016, Nick Galbreath
Copyright (c) 2017-2024, libinjection Contributors
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

1. Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

https://github.com/libinjection/libinjection
http://opensource.org/licenses/BSD-3-Clause
```

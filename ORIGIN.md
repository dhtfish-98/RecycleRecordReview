# Source and contribution record

Technical source: [abelcheung/rifiuti2](https://github.com/abelcheung/rifiuti2) at fixed commit `40f185bb7535355c07d9fdef736b87af6b239c63`. License: `BSD-3-Clause`; the original license text and original copyright notices are preserved.

New implementation author: **dhtfish98**. This project implements the explicitly selected standalone scope below. It is not presented as original ownership of the upstream algorithms or as a full rewrite of an upstream platform. No source files have merely been renamed into the runtime package.

Scope: Isolated Windows Recycle Bin $I versions 1 and 2: exact record sizing, UTF-16 path envelope, terminator/padding, declared size and representable FILETIME; paths are reduced to character counts and absolute/relative declaration.

The upstream entry points, format layouts and relevant default file/network/execution paths were inspected in the fixed files listed in SOURCE_MANIFEST.json. Complete new runtime files are reviewed separately; this does not imply audit of unselected upstream platform code.

Excluded upstream capabilities: INFO2, directory scanning, matching $R files, recovery and content export.

The repository owner must verify their actual contribution and authorization before using this record in an application. No CVE, rejected-model task, CVP acceptance or personal identity evidence has been invented.

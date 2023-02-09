# GhidraGoAnalyzer plugin

_TL;DR:
This project is no longer in development, there is a great `Ghidra_GolangAnalyzerExtension`
plugin which you can use for in-depth Go binary analysis in Ghidra:
https://github.com/mooncat-greenpy/Ghidra_GolangAnalyzerExtension_

This was an attempt to create a Ghidra plugin that introduces a Go analysis
implementation offering enhancements and features on top of what is already
available in existing Ghidra Go plugins such as gotools.

These enhancements include:
- support for all executable formats (PE/ELF/Mach-O)
- support for x86 and ARM
- support for both 32 and 64-bit binaries
- support for all Go versions (1.2+, 1.16+, 1.18+)
- extraction of function names
- extraction of function parameters
- extraction of function return values
- extraction of file names
- data type creation and mapping
- struct enumeration and mapping
- accompanying tests (unit and integration) for all implemented features

After two days spent on developing function extraction for all Go versions and
executable formats, I have found the `Ghidra_GolangAnalyzerExtension` plugin
available here:
https://github.com/mooncat-greenpy/Ghidra_GolangAnalyzerExtension

`Ghidra_GolangAnalyzerExtension` is being worked on for the past 
several years and works very well. Since there is no point to recreate what is 
already done, I have decided to stop working on this project and enrich the
`Ghidra_GolangAnalyzerExtension` via PRs if ever needed.

The `GhidraGoAnalyzer` project is posted here as a potential code reference 
for other plugin creators or just simple knowledge keeping. The project 
successfully parses pclntab and extracts the function names to create them in Ghidra.
All features have accompanying tests as per enhancement philosophy set out in
the bullet points above.
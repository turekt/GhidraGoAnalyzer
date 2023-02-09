package ghidra.app.go;

import ghidra.app.go.lntab.data.LineTable;
import ghidra.program.model.listing.Program;

import java.util.Map;

public record ProgramTestCase(
        Program program,
        LineTable lineTable,
        Map<Long, String> recoveredFuncs
) {}

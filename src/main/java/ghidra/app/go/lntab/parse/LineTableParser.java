package ghidra.app.go.lntab.parse;

import ghidra.app.go.lntab.data.LineTable;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;

public interface LineTableParser {

    void parse(LineTable lineTable, Memory memory) throws MemoryAccessException;
}

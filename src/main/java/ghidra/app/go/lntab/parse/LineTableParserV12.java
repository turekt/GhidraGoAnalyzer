package ghidra.app.go.lntab.parse;

import ghidra.app.go.lntab.data.LineTable;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;

public class LineTableParserV12 extends AbstractLineTableParser {

    @Override
    public void parse(LineTable lineTable, Memory memory) throws MemoryAccessException {
        super.parse(lineTable, memory);
        lineTable.setFuncCount(offsetLnData(0).getLong());
        long funcTabSize = (lineTable.getFuncCount() * 2 + 1) * lineTable.getFuncTabValueSize();
        lineTable.setFuncTabSize(funcTabSize);

        long fileTabOffset = slice(LineTable.HEADER_SIZE + funcTabSize, Integer.BYTES).getLong();
        lineTable.setFileTabOffset(fileTabOffset);
        lineTable.setFileCount(slice(fileTabOffset, Integer.BYTES).getLong());
    }
}

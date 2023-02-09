package ghidra.app.go.lntab.parse;

import ghidra.app.go.lntab.data.LineTable;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;

public class LineTableParserV116 extends AbstractLineTableParser {

    @Override
    public void parse(LineTable lineTable, Memory memory) throws MemoryAccessException {
        super.parse(lineTable, memory);
        lineTable.setFuncCount(offsetLnData(0).getLong());
        lineTable.setFileCount(offsetLnData(1).getLong());
        lineTable.setFuncNameTabOffset(offsetLnData(2).getLong());
        lineTable.setCuTabOffset(offsetLnData(3).getLong());
        lineTable.setFileTabOffset(offsetLnData(4).getLong());
        lineTable.setPcTabOffset(offsetLnData(5).getLong());
        lineTable.setFuncTabOffset(offsetLnData(6).getLong());
        lineTable.setFuncTabSize((lineTable.getFuncCount() * 2 + 1) * lineTable.getFuncTabValueSize());
    }
}

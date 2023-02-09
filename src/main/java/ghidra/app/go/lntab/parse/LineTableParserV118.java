package ghidra.app.go.lntab.parse;

import ghidra.app.go.lntab.data.LineTable;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;

public class LineTableParserV118 extends AbstractLineTableParser {

    @Override
    public void parse(LineTable lineTable, Memory memory) throws MemoryAccessException {
        super.parse(lineTable, memory);
        lineTable.setFuncCount(offsetLnData(0).getLong());
        lineTable.setFileCount(offsetLnData(1).getLong());
        lineTable.setTextStart(offsetLnData(2).getLong());
        lineTable.setFuncNameTabOffset(offsetLnData(3).getLong());
        lineTable.setCuTabOffset(offsetLnData(4).getLong());
        lineTable.setFileTabOffset(offsetLnData(5).getLong());
        lineTable.setPcTabOffset(offsetLnData(6).getLong());
        lineTable.setFuncTabOffset(offsetLnData(7).getLong());
        lineTable.setFuncTabSize((lineTable.getFuncCount() * 2 + 1) * lineTable.getFuncTabValueSize());
    }
}

package ghidra.app.go.recovery.func;

import ghidra.app.go.lntab.data.LineTable;
import ghidra.app.go.lntab.parse.AbstractLineTableParser;
import ghidra.app.go.recovery.GoRecovery;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

import java.nio.ByteBuffer;

public abstract class GoFuncRecovery extends AbstractLineTableParser implements GoRecovery {

    static byte[] FUNC_NAME_DELIMITER = new byte[] { 0x00 };

    public Function createFunction(Program p, String funcName, Address funcTextAddress) throws Exception {
        int id = p.startTransaction("func_create");
        Function f = p.getFunctionManager().getFunctionAt(funcTextAddress);
        if (f == null) {
            f = p.getFunctionManager().createFunction(funcName, funcTextAddress, null, SourceType.ANALYSIS);
        } else {
            f.setName(funcName, SourceType.ANALYSIS);
        }
        p.endTransaction(id, true);
        return f;
    }

    public byte[] extractFunctionName(Program p, Address funcNameAddress, TaskMonitor monitor) throws Exception {
        Memory mem = p.getMemory();
        // find first \0 starting from func name value address
        Address funcNameAddrEnd = mem.findBytes(funcNameAddress, FUNC_NAME_DELIMITER, null, true, monitor);
        // extract name (func name value address until \0)
        byte[] funcNameBytes = new byte[(int)(funcNameAddrEnd.getOffset()-funcNameAddress.getOffset())];
        mem.getBytes(funcNameAddress, funcNameBytes);
        return funcNameBytes;
    }

    public void recover(Program p, MessageLog log, TaskMonitor monitor, LineTable lineTable)
            throws Exception {
        super.parse(lineTable, p.getMemory());
    }
}

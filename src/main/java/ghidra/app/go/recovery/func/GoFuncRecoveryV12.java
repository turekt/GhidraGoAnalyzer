package ghidra.app.go.recovery.func;

import ghidra.app.go.lntab.data.LineTable;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public class GoFuncRecoveryV12 extends GoFuncRecovery {

    @Override
    public void recover(Program p, MessageLog log, TaskMonitor monitor, LineTable lineTable) throws Exception {
        super.recover(p, log, monitor, lineTable);
        int ptrSize = lineTable.getPtrSize();
        Address funcTabIter = lineTable.offset(LineTable.HEADER_SIZE + ptrSize);
        for (int i = 0; i < lineTable.getFuncCount(); i++) {
            long funcTextAddrValue = slice(funcTabIter).getLong();
            funcTabIter = funcTabIter.add(ptrSize);

            long off1 = slice(funcTabIter).getLong();
            funcTabIter = funcTabIter.add(ptrSize);
            Address offsetAddr = lineTable.getAddress().add(off1 + ptrSize);
            long off2 = slice(offsetAddr, 0, Integer.BYTES).getLong();
            Address funcNameAddress = lineTable.getAddress().add(off2);

            Address funcText = p.getAddressFactory().getDefaultAddressSpace().getAddress(funcTextAddrValue);
            byte[] funcNameBytes = extractFunctionName(p, funcNameAddress, monitor);
            createFunction(p, new String(funcNameBytes), funcText);
        }
    }
}

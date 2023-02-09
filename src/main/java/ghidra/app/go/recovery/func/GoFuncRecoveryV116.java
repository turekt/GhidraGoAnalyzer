package ghidra.app.go.recovery.func;

import ghidra.app.go.lntab.data.GoVersion;
import ghidra.app.go.lntab.data.LineTable;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public class GoFuncRecoveryV116 extends GoFuncRecovery {

    @Override
    public void recover(Program p, MessageLog log, TaskMonitor monitor, LineTable lineTable) throws Exception {
        super.recover(p, log, monitor, lineTable);
        Address funcTabStart = lineTable.offset(lineTable.getFuncTabOffset());
        Address funcNameTabStart = lineTable.offset(lineTable.getFuncNameTabOffset());
        // use this for iteration purposes
        Address funcTabIter = lineTable.offset(lineTable.getFuncTabOffset());

        for (long i = 0; i < lineTable.getFuncCount(); i++) {
            // func code address is the first value
            long funcTextAddrValue = slice(funcTabIter).getLong();
            if (lineTable.getVersion().getVersionNumber() >= GoVersion.V118.getVersionNumber()) {
                // in version >=118 first value is an offset, not direct memory address
                funcTextAddrValue += lineTable.getTextStart();
            }

            // second value is an offset from func tab start pointing to an
            // address that contains an offset* from func name tab start
            // which points to the name of the function
            //
            // off1 = *(func_tab_start_addr+func_tab_value_size)
            // off2 = *(func_tab_start_addr+off1+func_tab_value_size)
            // name = *(func_name_tab_start+off2)
            //
            // move to next value
            funcTabIter = funcTabIter.add(lineTable.getFuncTabValueSize());
            // next value is off1, so we add func_tab_value_size to it to get the address of off2
            long off1 = slice(funcTabIter).getLong() + lineTable.getFuncTabValueSize();
            Address funcNameTabOffAddr = funcTabStart.add(off1);
            funcTabIter = funcTabIter.add(lineTable.getFuncTabValueSize());
            // value of off2 is added to func_name_tab_start to get the address of func name value
            long off2 = slice(funcNameTabOffAddr).getLong();
            Address funcNameAddress = funcNameTabStart.add(off2);
            byte[] funcNameBytes = extractFunctionName(p, funcNameAddress, monitor);

            Address funcText = p.getAddressFactory().getDefaultAddressSpace().getAddress(funcTextAddrValue);
            createFunction(p, new String(funcNameBytes), funcText);
        }
    }
}

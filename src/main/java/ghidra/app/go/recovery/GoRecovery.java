package ghidra.app.go.recovery;

import ghidra.app.go.lntab.data.LineTable;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public interface GoRecovery {

    void recover(Program p, MessageLog log, TaskMonitor monitor, LineTable lineTable) throws Exception;
}

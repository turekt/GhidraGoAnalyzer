package ghidra.app.go.analysis;

import ghidra.app.go.lntab.data.GoVersion;
import ghidra.app.go.lntab.data.LineTable;
import ghidra.app.go.recovery.GoRecovery;
import ghidra.app.go.recovery.func.GoFuncRecoveryV116;
import ghidra.app.go.recovery.func.GoFuncRecoveryV12;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public class GoFuncAnalysis implements GoAnalysis {

    @Override
    public void analyze(Program p, MessageLog log, TaskMonitor monitor, LineTable lineTable) throws Exception {
        GoRecovery recovery = lineTable.getVersion() == GoVersion.V12
                ? new GoFuncRecoveryV12()
                : new GoFuncRecoveryV116();
        recovery.recover(p, log, monitor, lineTable);
    }
}

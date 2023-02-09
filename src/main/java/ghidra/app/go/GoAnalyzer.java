package ghidra.app.go;

import ghidra.app.go.analysis.GoAnalysis;
import ghidra.app.go.analysis.GoFuncAnalysis;
import ghidra.app.go.lntab.LineTableScanner;
import ghidra.app.go.lntab.data.LineTable;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.NotFoundException;
import ghidra.util.task.TaskMonitor;

public class GoAnalyzer extends AbstractAnalyzer {

    private static final GoAnalysis[] ANALYSES = new GoAnalysis[] {
            new GoFuncAnalysis()
    };

    public GoAnalyzer() {
        super("Go Analyzer", "Analyzes Go binary symbols", AnalyzerType.BYTE_ANALYZER);
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) {
        LineTableScanner lineTableScanner = new LineTableScanner(program);
        try {
            lineTableScanner.scan();
        } catch(NotFoundException | MemoryAccessException ex) {
            log.appendException(ex);
            return false;
        }
        LineTable lineTable = lineTableScanner.getLineTable();
        for (GoAnalysis analysis : ANALYSES) {
            try {
                analysis.analyze(program, log, monitor, lineTable);
            } catch (Exception e) {
                log.appendException(e);
            }
        }
        return true;
    }

    @Override
    public boolean canAnalyze(Program program) {
        return true;
    }

    @Override
    public boolean getDefaultEnablement(Program program) {
        return false;
    }
}

package ghidra.app.go.analysis.func;

import ghidra.app.go.ProgramTest;
import ghidra.app.go.ProgramTestCase;
import ghidra.app.go.analysis.GoFuncAnalysis;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import org.junit.Assert;
import org.junit.Test;

import java.util.Map;

/**
 * Parameterized tests seem to be incompatible with Ghidra test suite due to
 * necessary invocation of Application.initializeApplication before any static
 * method is called (@Parameters require public static modifiers).
 * When initializeApplication is invoked then the test fails due to second
 * initialization executed by AbstractGenericTest. This could mean that it is
 * necessary to manually initialize Ghidra test application in order to leverage
 * parameterized tests.
 * Until this is investigated, each test is its own @Test.
 */
public class GoFuncAnalysisTest extends ProgramTest {

    @Test
    public void testFuncAnalysisElfLE116() throws Exception {
        recover(elfProgramLE116());
    }

    @Test
    public void testFuncAnalysisElfLE118() throws Exception {
        recover(elfProgramLE118());
    }

    @Test
    public void testFuncAnalysisElfBE118() throws Exception {
        recover(elfProgramBE118());
    }

    @Test
    public void testFuncAnalysisPeLE118() throws Exception {
        recover(peProgramLE118());
    }

    @Test
    public void testFuncAnalysisMachoLE12() throws Exception {
        recover(machoProgramLE12());
    }

    private void recover(ProgramTestCase testCase) throws Exception {
        GoFuncAnalysis funcAnalysis = new GoFuncAnalysis();
        funcAnalysis.analyze(testCase.program(), new MessageLog(), TaskMonitor.DUMMY, testCase.lineTable());
        Program program = testCase.program();
        for (Map.Entry<Long, String> entry : testCase.recoveredFuncs().entrySet()) {
            Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(entry.getKey());
            Function f = program.getFunctionManager().getFunctionAt(addr);
            Assert.assertNotNull(f);
            Assert.assertEquals(entry.getValue(), f.getName());
        }
    }
}

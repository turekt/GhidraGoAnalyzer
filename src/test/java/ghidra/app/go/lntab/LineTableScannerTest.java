package ghidra.app.go.lntab;

import ghidra.app.go.ProgramTest;
import ghidra.app.go.ProgramTestCase;
import ghidra.app.go.lntab.data.LineTable;
import org.junit.Assert;
import org.junit.Test;

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
public class LineTableScannerTest extends ProgramTest {

    @Test
    public void testScanElfLE116() throws Exception {
        runTestCase(elfProgramLE116());
    }

    @Test
    public void testScanElfLE118() throws Exception {
        runTestCase(elfProgramLE118());
    }

    @Test
    public void testScanElf32LE118() throws Exception {
        runTestCase(elfProgram32LE118());
    }

    @Test
    public void testScanElfBE118() throws Exception {
        runTestCase(elfProgramBE118());
    }

    @Test
    public void testScanPeLE118() throws Exception {
        runTestCase(peProgramLE118());
    }

    @Test
    public void testScanMachoLE12() throws Exception {
        runTestCase(machoProgramLE12());
    }

    private void runTestCase(ProgramTestCase testCase) throws Exception {
        LineTableScanner scanner = new LineTableScanner(testCase.program());
        scanner.scan();
        LineTable result = scanner.getLineTable();
        Assert.assertEquals(testCase.lineTable(), result);
    }
}

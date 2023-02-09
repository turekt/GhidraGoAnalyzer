package ghidra.app.go;

import generic.test.AbstractGenericTest;
import ghidra.app.go.lntab.data.GoVersion;
import ghidra.app.go.lntab.data.LineTable;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.app.util.opinion.MachoLoader;
import ghidra.app.util.opinion.PeLoader;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Program;

import java.nio.ByteOrder;
import java.util.HashMap;
import java.util.Map;

public class ProgramTest extends AbstractGenericTest {

    ProgramTestCase[] testCases() throws Exception {
        return new ProgramTestCase[] {
                machoProgramLE12(),
                peProgramLE118(),
                elfProgramLE116(),
                elfProgramLE118(),
                elfProgram32LE118(),
                elfProgramBE118(),
        };
    }

    protected ProgramTestCase machoProgramLE12() throws Exception {
        ProgramBuilder builder = new ProgramBuilder("peLE118", ProgramBuilder._X64);
        LineTable lineTable = new LineTable();
        Map<Long, String> recoveredFuncs = new HashMap<>(2);

        builder.createMemory("__gopclntab", "0x10ef760", 64);
        // header
        builder.setBytes("0x10ef760", "fb ff ff ff 00 00 01 08");
        lineTable.setEndianness(ByteOrder.LITTLE_ENDIAN);
        lineTable.setVersion(GoVersion.V12);
        lineTable.setQuantum(1);
        lineTable.setPtrSize(8);

        // func count
        builder.setBytes("0x10ef768", "02 00 00 00 00 00 00 00");
        lineTable.setFuncCount(2L);
        lineTable.setFuncTabSize(40L);

        // func tab
        builder.setBytes("0x10ef770", "00 10 00 01 00 00 00 00");
        builder.setBytes("0x10ef778", "f0 7d 00 00 00 00 00 00");
        builder.setBytes("0x10ef780", "70 10 00 01 00 00 00 00");
        builder.setBytes("0x10ef788", "28 7e 00 00 00 00 00 00");

        // file tab offset
        builder.setBytes("0x10ef790", "60 60 00 00 00 00 00 00");
        builder.setBytes("0x10f57c0", "01 00 00 00 00 00 00 00");
        lineTable.setFileCount(1L);
        lineTable.setFileTabOffset(0x6060L);

        // name offsets
        builder.setBytes("0x10f7558", "18 7e 00 00 00 00 00 00");
        builder.setBytes("0x10f7590", "70 7e 00 00 10 00 00 00");

        // names
        builder.setBytes("0x10f7578", "69 6e 74 65 72 6e 61 00");
        builder.setBytes("0x10f75d0", "69 6e 74 65 72 6e 65 00");
        builder.createEmptyFunction("FUN_10010000", "0x1001000", 16, DataType.DEFAULT);
        builder.createEmptyFunction("FUN_10010070", "0x1001070", 16, DataType.DEFAULT);
        recoveredFuncs.put(0x1001000L, "interna");
        recoveredFuncs.put(0x1001070L, "interne");

        Program program = builder.getProgram();
        long id = program.startTransaction("set Mach-o format");
        program.setExecutableFormat(MachoLoader.MACH_O_NAME);
        program.endTransaction((int)id, true);
        Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x10ef760);
        lineTable.setAddress(addr);
        return new ProgramTestCase(program, lineTable, recoveredFuncs);
    }

    protected ProgramTestCase peProgramLE118() throws Exception {
        ProgramBuilder builder = new ProgramBuilder("peLE118", ProgramBuilder._X64);
        LineTable lineTable = new LineTable();
        Map<Long, String> recoveredFuncs = new HashMap<>(2);

        // pclntab is hidden inside .text
        builder.createMemory(".text", "0x4d0950", 88);
        // header
        builder.setBytes("0x4d0960", "f0 ff ff ff 00 00 01 08");
        lineTable.setEndianness(ByteOrder.LITTLE_ENDIAN);
        lineTable.setVersion(GoVersion.V118);
        lineTable.setQuantum(1);
        lineTable.setPtrSize(8);

        // func count
        builder.setBytes("0x4d0968", "02 00 00 00 00 00 00 00");
        lineTable.setFuncCount(0x2L);

        // file count
        builder.setBytes("0x4d0970", "b3 00 00 00 00 00 00 00");
        lineTable.setFileCount(0xb3L);

        // start address
        builder.setBytes("0x4d0978", "00 10 40 00 00 00 00 00");
        lineTable.setTextStart(0x401000L);

        // func name table offset
        builder.setBytes("0x4d0980", "60 00 00 00 00 00 00 00");
        lineTable.setFuncNameTabOffset(0x60L);

        // cu tab offset
        builder.setBytes("0x4d0988", "40 bc 00 00 00 00 00 00");
        lineTable.setCuTabOffset(0xbc40L);

        // file tab offset
        builder.setBytes("0x4d0990", "e0 c3 00 00 00 00 00 00");
        lineTable.setFileTabOffset(0xc3e0L);

        // pc tab offset
        builder.setBytes("0x4d0998", "df 00 00 00 00 00 00");
        lineTable.setPcTabOffset(0xdfL);

        // func tab offset
        builder.setBytes("0x4d09a0", "e0 c9 03 00 00 00 00 00");
        builder.setBytes("0x4d09a8", "00 00 00 00 00 00 00 00");
        builder.setBytes("0x4d09b0", "00 00 00 00 00 00 00 00");
        builder.setBytes("0x4d09b8", "00 00 00 00 00 00 00 00");
        lineTable.setFuncTabOffset(0x3c9e0L);

        // start of func name tab
        builder.setBytes("0x4d09c0", "69 6e 74 65 72 6e 61 00"); // interna
        builder.setBytes("0x4d09c8", "69 6e 74 65 72 6e 65 00"); // interne

        // func tab memory
        builder.createMemory(".functab", "0x50d340", 16);
        builder.setBytes("0x50d340", "00 00 00 00 70 2d 00 00");
        builder.setBytes("0x50d348", "80 00 00 00 78 2d 00 00");

        // func name tab offset memory
        builder.createMemory(".functabnmoffs", "0x5100b4", 8);
        builder.setBytes("0x5100b4", "00 00 00 00");
        builder.setBytes("0x5100bc", "08 00 00 00");

        // functions
        builder.createEmptyFunction("FUN_4010000", "0x401000", 16, DataType.DEFAULT);
        builder.createEmptyFunction("FUN_4010080", "0x401080", 16, DataType.DEFAULT);
        recoveredFuncs.put(0x401000L, "interna");
        recoveredFuncs.put(0x401080L, "interne");

        Program program = builder.getProgram();
        long id = program.startTransaction("set PE format");
        program.setExecutableFormat(PeLoader.PE_NAME);
        program.endTransaction((int)id, true);
        Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x4d0960);
        lineTable.setAddress(addr);
        return new ProgramTestCase(program, lineTable, recoveredFuncs);
    }

    protected ProgramTestCase elfProgramLE116() throws Exception {
        ProgramBuilder builder = new ProgramBuilder("elfLE116", ProgramBuilder._X64);
        LineTable lineTable = new LineTable();
        Map<Long, String> recoveredFuncs = new HashMap<>(2);

        builder.createMemory(".gopclntab", "0x6e2820", 72);
        // header
        builder.setBytes("0x6e2820", "fa ff ff ff 00 00 01 08");
        lineTable.setEndianness(ByteOrder.LITTLE_ENDIAN);
        lineTable.setVersion(GoVersion.V116);
        lineTable.setQuantum(1);
        lineTable.setPtrSize(8);

        // func count
        builder.setBytes("0x6e2828", "02 00 00 00 00 00 00 00");
        lineTable.setFuncCount(0x2L);

        // file count
        builder.setBytes("0x6e2830", "f4 01 00 00 00 00 00 00");
        lineTable.setFileCount(0x1f4L);

        // func name table offset
        builder.setBytes("0x6e2838", "40 00 00 00 00 00 00 00");
        lineTable.setFuncNameTabOffset(0x40L);

        // cu tab offset
        builder.setBytes("0x6e2840", "c0 ae 02 00 00 00 00 00");
        lineTable.setCuTabOffset(0x2aec0L);

        // file tab offset
        builder.setBytes("0x6e2848", "60 d0 02 00 00 00 00 00");
        lineTable.setFileTabOffset(0x2d060L);

        // pc tab offset
        builder.setBytes("0x6e2850", "40 25 03 00 00 00 00 00");
        lineTable.setPcTabOffset(0x32540L);

        // func tab offset
        builder.setBytes("0x6e2858", "a0 63 0b 00 00 00 00 00");
        lineTable.setFuncTabOffset(0xb63a0L);

        // start of func name tab
        builder.setBytes("0x6e2860", "69 6e 74 65 72 6e 61 00"); // interna
        builder.setBytes("0x6e2868", "69 6e 74 65 72 6e 65 00"); // interne

        // func tab memory
        builder.createMemory(".functab", "0x798bc0", 32);
        builder.setBytes("0x798bc0", "00 10 40 00 00 00 00 00");
        builder.setBytes("0x798bc8", "18 1b 01 00 00 00 00 00");
        builder.setBytes("0x798bd0", "60 10 40 00 00 00 00 00");
        builder.setBytes("0x798bd8", "20 1b 01 00 00 00 00 00");

        // func name tab offset memory
        builder.createMemory(".functabnmoffs", "0x7aa6e0", 16);
        builder.setBytes("0x7aa6e0", "00 00 00 00 00 00 00 00");
        builder.setBytes("0x7aa6e8", "08 00 00 00 00 00 00 00");

        // functions
        builder.createEmptyFunction("FUN_4010000", "0x401000", 16, DataType.DEFAULT);
        builder.createEmptyFunction("FUN_4010060", "0x401060", 16, DataType.DEFAULT);
        recoveredFuncs.put(0x401000L, "interna");
        recoveredFuncs.put(0x401060L, "interne");

        Program program = builder.getProgram();
        long id = program.startTransaction("set ELF format");
        program.setExecutableFormat(ElfLoader.ELF_NAME);
        program.endTransaction((int)id, true);
        Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x6e2820);
        lineTable.setAddress(addr);
        return new ProgramTestCase(program, lineTable, recoveredFuncs);
    }

    protected ProgramTestCase elfProgramBE118() throws Exception {
        ProgramBuilder builder = new ProgramBuilder("elfBE118", ProgramBuilder._X64);
        LineTable lineTable = new LineTable();
        Map<Long, String> recoveredFuncs = new HashMap<>(2);

        builder.createMemory(".gopclntab", "0x4bb020", 72);
        // header
        builder.setBytes("0x4bb020", "ff ff ff f0 00 00 01 08");
        lineTable.setEndianness(ByteOrder.BIG_ENDIAN);
        lineTable.setVersion(GoVersion.V118);
        lineTable.setQuantum(1);
        lineTable.setPtrSize(8);

        // func count
        builder.setBytes("0x4bb028", "00 00 00 00 00 00 00 02");
        lineTable.setFuncCount(0x2L);

        // file count
        builder.setBytes("0x4bb030", "00 00 00 00 00 00 00 b9");
        lineTable.setFileCount(0xb9L);

        // start address
        builder.setBytes("0x4bb038", "00 00 00 00 00 40 10 00");
        lineTable.setTextStart(0x401000L);

        // func name table offset
        builder.setBytes("0x4bb040", "00 00 00 00 00 00 00 60");
        lineTable.setFuncNameTabOffset(0x60L);

        // cu tab offset
        builder.setBytes("0x4bb048", "00 00 00 00 00 00 ba e0");
        lineTable.setCuTabOffset(0xbae0L);

        // file tab offset
        builder.setBytes("0x4bb050", "00 00 00 00 00 00 c2 e0");
        lineTable.setFileTabOffset(0xc2e0L);

        // pc tab offset
        builder.setBytes("0x4bb058", "00 00 00 00 00 00 de a0");
        lineTable.setPcTabOffset(0xdea0L);

        // func tab offset
        builder.setBytes("0x4bb060", "00 00 00 00 00 03 90 40");
        builder.setBytes("0x4bb068", "00 00 00 00 00 00 00 00");
        builder.setBytes("0x4bb070", "00 00 00 00 00 00 00 00");
        builder.setBytes("0x4bb078", "00 00 00 00 00 00 00 00");
        lineTable.setFuncTabOffset(0x39040L);

        // start of func name tab
        builder.setBytes("0x4bb080", "69 6e 74 65 72 6e 61 00"); // interna
        builder.setBytes("0x4bb088", "69 6e 74 65 72 6e 65 00"); // interne

        // func tab memory
        builder.createMemory(".functab", "0x4f4060", 16);
        builder.setBytes("0x4f4060", "00 00 00 00 00 00 2c 78");
        builder.setBytes("0x4f4068", "00 00 00 60 00 00 2c 7c");

        // func name tab offset memory
        builder.createMemory(".functabnmoffs", "0x4f6cdc", 8);
        builder.setBytes("0x4f6cdc", "00 00 00 00");
        builder.setBytes("0x4f6ce0", "00 00 00 08");

        // functions
        builder.createEmptyFunction("FUN_4010000", "0x401000", 16, DataType.DEFAULT);
        builder.createEmptyFunction("FUN_4010060", "0x401060", 16, DataType.DEFAULT);
        recoveredFuncs.put(0x401000L, "interna");
        recoveredFuncs.put(0x401060L, "interne");

        Program program = builder.getProgram();
        long id = program.startTransaction("set ELF format");
        program.setExecutableFormat(ElfLoader.ELF_NAME);
        program.endTransaction((int)id, true);
        Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x4bb020);
        lineTable.setAddress(addr);
        return new ProgramTestCase(program, lineTable, recoveredFuncs);
    }

    protected ProgramTestCase elfProgram32LE118() throws Exception {
        ProgramBuilder builder = new ProgramBuilder("elfLE118-32", ProgramBuilder._X86);
        LineTable lineTable = new LineTable();
        Map<Long, String> recoveredFuncs = new HashMap<>(2);

        builder.createMemory(".gopclntab", "0x80fa140", 72);
        // header
        builder.setBytes("0x80fa140", "f0 ff ff ff 00 00 01 04");
        lineTable.setEndianness(ByteOrder.LITTLE_ENDIAN);
        lineTable.setVersion(GoVersion.V118);
        lineTable.setQuantum(1);
        lineTable.setPtrSize(4);

        // func count
        builder.setBytes("0x80fa148", "02 00 00 00");
        lineTable.setFuncCount(0x2L);

        // file count
        builder.setBytes("0x80fa14c", "b9 00 00 00");
        lineTable.setFileCount(0xb9L);

        // start address
        builder.setBytes("0x80fa150", "00 90 04 08");
        lineTable.setTextStart(0x08049000L);

        // func name table offset
        builder.setBytes("0x80fa154", "40 00 00 00");
        lineTable.setFuncNameTabOffset(0x40L);

        // cu tab offset
        builder.setBytes("0x80fa158", "bb 20 00 00");
        lineTable.setCuTabOffset(0x20bbL);

        // file tab offset
        builder.setBytes("0x80fa15c", "c2 c0 00 00");
        lineTable.setFileTabOffset(0xc0c2L);

        // pc tab offset
        builder.setBytes("0x80fa160", "20 df 00 00");
        lineTable.setPcTabOffset(0xdf20L);

        // func tab offset
        builder.setBytes("0x80fa164", "80 af 03 00 00 00 00 00");
        builder.setBytes("0x80fa168", "00 00 00 00 00 00 00 00");
        builder.setBytes("0x80fa170", "00 00 00 00 00 00 00 00");
        builder.setBytes("0x80fa174", "00 00 00 00 00 00 00 00");
        builder.setBytes("0x80fa178", "00 00 00 00 00 00 00 00");
        builder.setBytes("0x80fa17c", "00 00 00 00 00 00 00 00");
        lineTable.setFuncTabOffset(0x3af80L);

        // start of func name tab
        builder.setBytes("0x80fa180", "69 6e 74 65 72 6e 61 00"); // interna
        builder.setBytes("0x80fa188", "69 6e 74 65 72 6e 65 00"); // interne

        // func tab memory
        builder.createMemory(".functab", "0x81350c0", 16);
        builder.setBytes("0x81350c0", "00 00 00 00 0c 2e 00 00");
        builder.setBytes("0x81350c8", "40 00 00 00 10 2e 00 00");

        // func name tab offset memory
        builder.createMemory(".functabnmoffs", "0x4f6cdc", 8);
        builder.setBytes("0x8137ed0", "00 00 00 00");
        builder.setBytes("0x8137ed4", "08 00 00 00");

        // functions
        builder.createEmptyFunction("FUN_8049000", "0x8049000", 16, DataType.DEFAULT);
        builder.createEmptyFunction("FUN_8049040", "0x8049040", 16, DataType.DEFAULT);
        recoveredFuncs.put(0x08049000L, "interna");
        recoveredFuncs.put(0x08049040L, "interne");

        Program program = builder.getProgram();
        long id = program.startTransaction("set ELF format");
        program.setExecutableFormat(ElfLoader.ELF_NAME);
        program.endTransaction((int)id, true);
        Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x80fa140);
        lineTable.setAddress(addr);
        return new ProgramTestCase(program, lineTable, recoveredFuncs);
    }

    protected ProgramTestCase elfProgramLE118() throws Exception {
        ProgramBuilder builder = new ProgramBuilder("elfLE118", ProgramBuilder._X64);
        LineTable lineTable = new LineTable();
        Map<Long, String> recoveredFuncs = new HashMap<>(2);

        builder.createMemory(".gopclntab", "0x4bb020", 72);
        // header
        builder.setBytes("0x4bb020", "f0 ff ff ff 00 00 01 08");
        lineTable.setEndianness(ByteOrder.LITTLE_ENDIAN);
        lineTable.setVersion(GoVersion.V118);
        lineTable.setQuantum(1);
        lineTable.setPtrSize(8);

        // func count
        builder.setBytes("0x4bb028", "02 00 00 00 00 00 00 00");
        lineTable.setFuncCount(0x2L);

        // file count
        builder.setBytes("0x4bb030", "b9 00 00 00 00 00 00 00");
        lineTable.setFileCount(0xb9L);

        // start address
        builder.setBytes("0x4bb038", "00 10 40 00 00 00 00 00");
        lineTable.setTextStart(0x401000L);

        // func name table offset
        builder.setBytes("0x4bb040", "60 00 00 00 00 00 00 00");
        lineTable.setFuncNameTabOffset(0x60L);

        // cu tab offset
        builder.setBytes("0x4bb048", "e0 ba 00 00 00 00 00 00");
        lineTable.setCuTabOffset(0xbae0L);

        // file tab offset
        builder.setBytes("0x4bb050", "e0 c2 00 00 00 00 00 00");
        lineTable.setFileTabOffset(0xc2e0L);

        // pc tab offset
        builder.setBytes("0x4bb058", "a0 de 00 00 00 00 00 00");
        lineTable.setPcTabOffset(0xdea0L);

        // func tab offset
        builder.setBytes("0x4bb060", "40 90 03 00 00 00 00 00");
        builder.setBytes("0x4bb068", "00 00 00 00 00 00 00 00");
        builder.setBytes("0x4bb070", "00 00 00 00 00 00 00 00");
        builder.setBytes("0x4bb078", "00 00 00 00 00 00 00 00");
        lineTable.setFuncTabOffset(0x39040L);

        // start of func name tab
        builder.setBytes("0x4bb080", "69 6e 74 65 72 6e 61 00"); // interna
        builder.setBytes("0x4bb088", "69 6e 74 65 72 6e 65 00"); // interne

        // func tab memory
        builder.createMemory(".functab", "0x4f4060", 16);
        builder.setBytes("0x4f4060", "00 00 00 00 78 2c 00 00");
        builder.setBytes("0x4f4068", "40 00 00 00 7c 2c 00 00");

        // func name tab offset memory
        builder.createMemory(".functabnmoffs", "0x4f6cdc", 8);
        builder.setBytes("0x4f6cdc", "00 00 00 00");
        builder.setBytes("0x4f6ce0", "08 00 00 00");

        // functions
        builder.createEmptyFunction("FUN_4010000", "0x401000", 16, DataType.DEFAULT);
        builder.createEmptyFunction("FUN_4010040", "0x401040", 16, DataType.DEFAULT);
        recoveredFuncs.put(0x401000L, "interna");
        recoveredFuncs.put(0x401040L, "interne");

        Program program = builder.getProgram();
        long id = program.startTransaction("set ELF format");
        program.setExecutableFormat(ElfLoader.ELF_NAME);
        program.endTransaction((int)id, true);
        Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x4bb020);
        lineTable.setAddress(addr);
        return new ProgramTestCase(program, lineTable, recoveredFuncs);
    }
}

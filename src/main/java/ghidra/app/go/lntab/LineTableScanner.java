package ghidra.app.go.lntab;

import ghidra.app.go.lntab.data.GoVersion;
import ghidra.app.go.lntab.data.LineTable;
import ghidra.app.go.lntab.parse.LineTableParser;
import ghidra.app.go.lntab.parse.LineTableParserFactory;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.app.util.opinion.MachoLoader;
import ghidra.app.util.opinion.PeLoader;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.NotFoundException;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;

public class LineTableScanner {

    public static final Map<String, String[]> PCLNTAB_EXEC_FMT = Map.of(
            ElfLoader.ELF_NAME, LineTable.PCLNTAB_NAME_LINUX,
            PeLoader.PE_NAME, LineTable.PCLNTAB_NAME_WINDOWS,
            MachoLoader.MACH_O_NAME, LineTable.PCLNTAB_NAME_MACHO
    );

    private final Program program;
    private final LineTable lineTable;

    public LineTableScanner(Program program) {
        this.program = program;
        this.lineTable = new LineTable();
    }

    public void scan() throws NotFoundException, MemoryAccessException {
        Address pclntab = locateLineTable();
        if (pclntab == null) {
            throw new NotFoundException("failed to locate pclntab");
        }

        byte[] content = new byte[LineTable.HEADER_SIZE];
        Memory mem = this.program.getMemory();
        mem.getBytes(pclntab, content);
        parseHeader(content);
        this.lineTable.setAddress(pclntab);

        LineTableParser parser = LineTableParserFactory.getParser(this.lineTable.getVersion());
        parser.parse(this.lineTable, mem);
    }

    private void parseHeader(byte[] header) throws NotFoundException {
        if (header[4] != 0 || header[5] != 0
                || (header[6] != 1 && header[6] != 2 && header[6] != 4)
                || (header[7] != 4 && header[7] != 8)) {
            throw new NotFoundException("pclntab magic validation");
        }

        byte[] magic = new byte[4];
        System.arraycopy(header, 0, magic, 0, magic.length);
        if (!version(magic, ByteOrder.LITTLE_ENDIAN) && !version(magic, ByteOrder.BIG_ENDIAN)) {
            throw new NotFoundException("pclntab version validation");
        }

        this.lineTable.setQuantum(Byte.toUnsignedInt(header[6]));
        this.lineTable.setPtrSize(Byte.toUnsignedInt(header[7]));
    }

    private Address locateLineTable() {
        String[] lntabNames = PCLNTAB_EXEC_FMT.get(this.program.getExecutableFormat());
        MemoryBlock pclntabBlock = null;
        for (int i = 0; i < lntabNames.length && pclntabBlock == null; i++) {
            pclntabBlock = this.program.getMemory().getBlock(lntabNames[i]);
        }
        return pclntabBlock != null ? pclntabBlock.getStart() : bruteforce();
    }

    private Address bruteforce() {
        ByteOrder[] orders = new ByteOrder[] {
                ByteOrder.LITTLE_ENDIAN,
                ByteOrder.BIG_ENDIAN
        };
        int[] versions = new int[] {
                GoVersion.MAGIC_GO_118,
                GoVersion.MAGIC_GO_116,
                GoVersion.MAGIC_GO_120,
                GoVersion.MAGIC_GO_12,
        };

        for (ByteOrder order : orders) {
            for (int version : versions) {
                byte[] bytes = ByteBuffer.allocate(6)
                        .order(order)
                        .putInt(version)
                        .put((byte)0)
                        .put((byte)0)
                        .array();

                Memory mem = this.program.getMemory();
                Address addr = mem.findBytes(mem.getMinAddress(), bytes, null, true, null);
                if (addr != null) {
                    // candidate found, verify
                    try {
                        byte[] header = new byte[LineTable.HEADER_SIZE];
                        this.program.getMemory().getBytes(addr, header);
                        parseHeader(header);
                    } catch (MemoryAccessException | NotFoundException ignored) {
                        continue;
                    }
                    return addr;
                }
            }
        }

        return null;
    }

    private boolean version(byte[] magicBytes, ByteOrder order) {
        int magic = ByteBuffer.wrap(magicBytes)
                .order(order)
                .getInt();

        switch (magic) {
            case GoVersion.MAGIC_GO_12 -> this.lineTable.setVersion(GoVersion.V12);
            case GoVersion.MAGIC_GO_116 -> this.lineTable.setVersion(GoVersion.V116);
            case GoVersion.MAGIC_GO_118 -> this.lineTable.setVersion(GoVersion.V118);
            case GoVersion.MAGIC_GO_120 -> this.lineTable.setVersion(GoVersion.V120);
            default -> {
                return false;
            }
        }
        this.lineTable.setEndianness(order);
        return true;
    }

    public LineTable getLineTable() {
        return lineTable;
    }
}

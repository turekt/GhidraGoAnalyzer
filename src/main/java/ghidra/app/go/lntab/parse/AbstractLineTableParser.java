package ghidra.app.go.lntab.parse;

import ghidra.app.go.lntab.data.LineTable;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public abstract class AbstractLineTableParser implements LineTableParser {

    LineTable lineTable;
    Memory memory;

    @Override
    public void parse(LineTable lineTable, Memory memory) throws MemoryAccessException {
        this.lineTable = lineTable;
        this.memory = memory;
    }

    public ByteBuffer slice(Address address) throws MemoryAccessException {
        return slice(address, 0, this.lineTable.getFuncTabValueSize());
    }
    
    public ByteBuffer slice(long offset, Integer size) throws MemoryAccessException {
        return slice(this.lineTable.getAddress(), offset, size);
    }

    public ByteBuffer slice(Address address, long offset, int size) throws MemoryAccessException {
        return slice(
                this.memory,
                address,
                this.lineTable.getEndianness(),
                offset,
                size,
                Long.BYTES
        );
    }

    public ByteBuffer slice(Memory memory, Address startAddress, ByteOrder order, long offset, int size, int alloc)
            throws MemoryAccessException {
        Address start = startAddress.add(offset);
        byte[] bytes = new byte[size];
        memory.getBytes(start, bytes);
        ByteBuffer b = ByteBuffer.allocate(alloc).order(order);
        byte [] m = new byte[alloc - size];
        if (order == ByteOrder.BIG_ENDIAN) {
            b.put(m).put(bytes);
        } else {
            b.put(bytes).put(m);
        }
        return b.rewind();
    }

    public ByteBuffer offsetLnData(long position) throws MemoryAccessException {
        int ptrSize = this.lineTable.getPtrSize();
        return slice(ptrSize * position + LineTable.HEADER_SIZE, ptrSize);
    }
}

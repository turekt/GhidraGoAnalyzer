package ghidra.app.go.lntab.data;

import ghidra.program.model.address.Address;

import java.nio.ByteOrder;
import java.util.Objects;

public class LineTable {

    public static final int HEADER_SIZE = 8;
    public static final String[] PCLNTAB_NAME_LINUX = {".gopclntab"};
    public static final String[] PCLNTAB_NAME_WINDOWS = {"runtime.pclntab", "runtime.epclntab", "pclntab", "epclntab"};
    public static final String[] PCLNTAB_NAME_MACHO = {"__gopclntab", "__TEXT __gopclntab"};

    private Address address;
    private ByteOrder endianness;
    private GoVersion version;
    private Integer quantum;
    private Integer ptrSize;
    private Long funcCount;
    private Long fileCount;
    private Long funcNameTabOffset;
    private Long cuTabOffset;
    private Long fileTabOffset;
    private Long pcTabOffset;
    private Long funcTabOffset;
    private Long funcTabSize;
    private Long textStart;

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        LineTable lineTable = (LineTable) o;
        return version == lineTable.version
                && address.getOffset() == lineTable.address.getOffset()
                && Objects.equals(endianness, lineTable.endianness)
                && Objects.equals(quantum, lineTable.quantum)
                && Objects.equals(ptrSize, lineTable.ptrSize)
                && Objects.equals(funcCount, lineTable.funcCount)
                && Objects.equals(fileCount, lineTable.fileCount)
                && Objects.equals(funcNameTabOffset, lineTable.funcNameTabOffset)
                && Objects.equals(cuTabOffset, lineTable.cuTabOffset)
                && Objects.equals(fileTabOffset, lineTable.fileTabOffset)
                && Objects.equals(pcTabOffset, lineTable.pcTabOffset)
                && Objects.equals(funcTabOffset, lineTable.funcTabOffset);
    }

    public Integer getFuncTabValueSize() {
        return switch (version) {
            case V12, V116 -> ptrSize;
            default -> 4;
        };
    }

    public Address offset(long offset) {
        return address.add(offset);
    }

    public Address getAddress() {
        return address;
    }

    public void setAddress(Address address) {
        this.address = address;
    }

    public ByteOrder getEndianness() {
        return endianness;
    }

    public void setEndianness(ByteOrder endianness) {
        this.endianness = endianness;
    }

    public GoVersion getVersion() {
        return version;
    }

    public void setVersion(GoVersion version) {
        this.version = version;
    }

    public Integer getQuantum() {
        return quantum;
    }

    public void setQuantum(Integer quantum) {
        this.quantum = quantum;
    }

    public Integer getPtrSize() {
        return ptrSize;
    }

    public void setPtrSize(Integer ptrSize) {
        this.ptrSize = ptrSize;
    }

    public Long getFuncCount() {
        return funcCount;
    }

    public void setFuncCount(Long funcCount) {
        this.funcCount = funcCount;
    }

    public Long getFileCount() {
        return fileCount;
    }

    public void setFileCount(Long fileCount) {
        this.fileCount = fileCount;
    }

    public Long getFuncNameTabOffset() {
        return funcNameTabOffset;
    }

    public void setFuncNameTabOffset(Long funcNameTabOffset) {
        this.funcNameTabOffset = funcNameTabOffset;
    }

    public Long getCuTabOffset() {
        return cuTabOffset;
    }

    public void setCuTabOffset(Long cuTabOffset) {
        this.cuTabOffset = cuTabOffset;
    }

    public Long getFileTabOffset() {
        return fileTabOffset;
    }

    public void setFileTabOffset(Long fileTabOffset) {
        this.fileTabOffset = fileTabOffset;
    }

    public Long getPcTabOffset() {
        return pcTabOffset;
    }

    public void setPcTabOffset(Long pcTabOffset) {
        this.pcTabOffset = pcTabOffset;
    }

    public Long getFuncTabOffset() {
        return funcTabOffset;
    }

    public void setFuncTabOffset(Long funcTabOffset) {
        this.funcTabOffset = funcTabOffset;
    }

    public Long getFuncTabSize() {
        return funcTabSize;
    }

    public void setFuncTabSize(Long funcTabSize) {
        this.funcTabSize = funcTabSize;
    }

    public Long getTextStart() {
        return textStart;
    }

    public void setTextStart(Long textStart) {
        this.textStart = textStart;
    }
}

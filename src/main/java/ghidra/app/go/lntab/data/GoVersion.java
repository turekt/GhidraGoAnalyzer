package ghidra.app.go.lntab.data;

public enum GoVersion {

    UNKNOWN("Unknown", -1),
    V12("1.2", 12),
    V116("1.16", 116),
    V118("1.18", 118),
    V120("1.20", 120);

    public static final int MAGIC_GO_12 = 0xfffffffb;
    public static final int MAGIC_GO_116 = 0xfffffffa;
    public static final int MAGIC_GO_118 = 0xfffffff0;
    public static final int MAGIC_GO_120 = 0xfffffff1;

    private final String version;
    private final int versionNumber;

    GoVersion(String version, int versionNumber) {
        this.version = version;
        this.versionNumber = versionNumber;
    }

    public String getVersion() {
        return version;
    }

    public int getVersionNumber() {
        return versionNumber;
    }
}

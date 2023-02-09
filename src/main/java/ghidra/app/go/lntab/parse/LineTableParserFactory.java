package ghidra.app.go.lntab.parse;

import ghidra.app.go.lntab.data.GoVersion;

public class LineTableParserFactory {

    public static LineTableParser getParser(GoVersion goVersion) {
        LineTableParser parser = null;
        switch (goVersion) {
            case V12 -> parser = new LineTableParserV12();
            case V116 -> parser = new LineTableParserV116();
            case V118, V120 -> parser = new LineTableParserV118();
        }
        return parser;
    }
}

package apk2project.javac;

import java.util.*;

final class Json {
    private Json() {}
    static String quote(String s) {
        if (s == null) return "null";
        StringBuilder b = new StringBuilder(s.length() + 16).append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> b.append("\\\"");
                case '\\' -> b.append("\\\\");
                case '\b' -> b.append("\\b");
                case '\f' -> b.append("\\f");
                case '\n' -> b.append("\\n");
                case '\r' -> b.append("\\r");
                case '\t' -> b.append("\\t");
                default -> {
                    if (c < 0x20) b.append(String.format("\\u%04x", (int)c));
                    else b.append(c);
                }
            }
        }
        return b.append('"').toString();
    }
    static String value(Object v) {
        if (v == null) return "null";
        if (v instanceof Number || v instanceof Boolean) return String.valueOf(v);
        if (v instanceof Map<?,?> m) {
            StringBuilder b = new StringBuilder("{"); boolean first = true;
            for (var e : m.entrySet()) {
                if (!first) b.append(','); first = false;
                b.append(quote(String.valueOf(e.getKey()))).append(':').append(value(e.getValue()));
            }
            return b.append('}').toString();
        }
        if (v instanceof Iterable<?> it) {
            StringBuilder b = new StringBuilder("["); boolean first = true;
            for (Object x : it) { if (!first) b.append(','); first = false; b.append(value(x)); }
            return b.append(']').toString();
        }
        if (v.getClass().isArray()) {
            StringBuilder b = new StringBuilder("["); int n = java.lang.reflect.Array.getLength(v);
            for (int i=0;i<n;i++) { if (i>0)b.append(','); b.append(value(java.lang.reflect.Array.get(v,i))); }
            return b.append(']').toString();
        }
        return quote(String.valueOf(v));
    }
}

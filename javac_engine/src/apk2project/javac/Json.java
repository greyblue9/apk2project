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
        if (v instanceof Object[] a) return arrayObjects(a);
        if (v instanceof boolean[] a) return arrayBooleans(a);
        if (v instanceof byte[] a) return arrayBytes(a);
        if (v instanceof short[] a) return arrayShorts(a);
        if (v instanceof int[] a) return arrayInts(a);
        if (v instanceof long[] a) return arrayLongs(a);
        if (v instanceof float[] a) return arrayFloats(a);
        if (v instanceof double[] a) return arrayDoubles(a);
        if (v instanceof char[] a) return arrayChars(a);
        return quote(String.valueOf(v));
    }
    private static String arrayObjects(Object[] a) {
        StringBuilder b = new StringBuilder("[");
        for (int i=0;i<a.length;i++) { if (i>0)b.append(','); b.append(value(a[i])); }
        return b.append(']').toString();
    }
    private static String arrayBooleans(boolean[] a) { StringBuilder b=new StringBuilder("["); for(int i=0;i<a.length;i++){if(i>0)b.append(',');b.append(a[i]);} return b.append(']').toString(); }
    private static String arrayBytes(byte[] a) { StringBuilder b=new StringBuilder("["); for(int i=0;i<a.length;i++){if(i>0)b.append(',');b.append(a[i]);} return b.append(']').toString(); }
    private static String arrayShorts(short[] a) { StringBuilder b=new StringBuilder("["); for(int i=0;i<a.length;i++){if(i>0)b.append(',');b.append(a[i]);} return b.append(']').toString(); }
    private static String arrayInts(int[] a) { StringBuilder b=new StringBuilder("["); for(int i=0;i<a.length;i++){if(i>0)b.append(',');b.append(a[i]);} return b.append(']').toString(); }
    private static String arrayLongs(long[] a) { StringBuilder b=new StringBuilder("["); for(int i=0;i<a.length;i++){if(i>0)b.append(',');b.append(a[i]);} return b.append(']').toString(); }
    private static String arrayFloats(float[] a) { StringBuilder b=new StringBuilder("["); for(int i=0;i<a.length;i++){if(i>0)b.append(',');b.append(a[i]);} return b.append(']').toString(); }
    private static String arrayDoubles(double[] a) { StringBuilder b=new StringBuilder("["); for(int i=0;i<a.length;i++){if(i>0)b.append(',');b.append(a[i]);} return b.append(']').toString(); }
    private static String arrayChars(char[] a) { StringBuilder b=new StringBuilder("["); for(int i=0;i<a.length;i++){if(i>0)b.append(',');b.append(quote(String.valueOf(a[i])));} return b.append(']').toString(); }

}

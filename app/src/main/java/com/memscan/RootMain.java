package com.memscan;

import java.io.*;
import java.nio.*;
import java.util.*;

/** Runs as root via app_process. Read-only memory scanner using /proc/<pid>/mem. */
public class RootMain {
    static final class El { int w; boolean wild, any, fl; long lo, hi; double dlo, dhi; }
    static final int CH = 4 << 20, MAXR = 300;

    public static void main(String[] args) throws Exception {
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        PrintStream out = new PrintStream(new FileOutputStream(FileDescriptor.out), true);
        String l;
        while ((l = in.readLine()) != null) {
            String[] p = l.split(" ", 3);
            try {
                if (p[0].equals("PID")) out.println("PID " + findPid(p[1]));
                else if (p[0].equals("SCAN")) scan(Integer.parseInt(p[1]), p[2], out);
                else if (p[0].equals("QUIT")) return;
            } catch (Throwable t) { out.println("ERR " + t); }
            out.println("END");
        }
    }

    static int findPid(String pkg) throws IOException {
        File[] fs = new File("/proc").listFiles();
        if (fs == null) return -1;
        for (File f : fs) {
            String n = f.getName();
            if (!n.matches("\\d+")) continue;
            try (FileInputStream is = new FileInputStream("/proc/" + n + "/cmdline")) {
                byte[] b = new byte[256]; int r = is.read(b);
                if (r <= 0) continue;
                int e = 0; while (e < r && b[e] != 0) e++;
                if (new String(b, 0, e).equals(pkg)) return Integer.parseInt(n);
            } catch (IOException ignored) {}
        }
        return -1;
    }

    /** Tokens: N:value (N=1,2,4,8)  f:value  d:value  w:N (skip N bytes). Value: x | a-b | a~b | * */
    static El[] parse(String s) {
        List<El> r = new ArrayList<>();
        for (String t : s.trim().split("\\s+")) {
            int c = t.indexOf(':');
            if (c < 1) throw new IllegalArgumentException("Bad token: " + t);
            String k = t.substring(0, c).toLowerCase(), v = t.substring(c + 1);
            El e = new El();
            if (k.equals("w")) { e.wild = true; e.w = Integer.parseInt(v); if (e.w < 1) throw new IllegalArgumentException("w must be >= 1"); }
            else if (k.equals("f") || k.equals("d")) {
                e.fl = true; e.w = k.equals("f") ? 4 : 8;
                if (v.equals("*")) e.any = true;
                else {
                    int i = v.indexOf('~');
                    double a = Double.parseDouble(i > 0 ? v.substring(0, i) : v);
                    double b = i > 0 ? Double.parseDouble(v.substring(i + 1)) : a;
                    if (e.w == 4) { a = (float) a; b = (float) b; }
                    e.dlo = a; e.dhi = b;
                }
            } else {
                e.w = Integer.parseInt(k);
                if (e.w != 1 && e.w != 2 && e.w != 4 && e.w != 8) throw new IllegalArgumentException("Bad size: " + k);
                if (v.equals("*")) e.any = true;
                else {
                    int i = v.indexOf('~'); if (i < 0) i = v.indexOf('-', 1);
                    e.lo = Long.decode(i > 0 ? v.substring(0, i) : v);
                    e.hi = i > 0 ? Long.decode(v.substring(i + 1)) : e.lo;
                }
            }
            r.add(e);
        }
        return r.toArray(new El[0]);
    }

    static boolean match(ByteBuffer b, int off, El[] els) {
        int o = off;
        for (El e : els) {
            if (!e.wild && !e.any) {
                if (e.fl) {
                    double v = e.w == 4 ? b.getFloat(o) : b.getDouble(o);
                    if (!(v >= e.dlo && v <= e.dhi)) return false;
                } else {
                    long s = e.w == 1 ? b.get(o) : e.w == 2 ? b.getShort(o) : e.w == 4 ? b.getInt(o) : b.getLong(o);
                    long u = e.w == 8 ? s : (s & ((1L << (8 * e.w)) - 1));
                    if (!((s >= e.lo && s <= e.hi) || (u >= e.lo && u <= e.hi))) return false;
                }
            }
            o += e.w;
        }
        return true;
    }

    static void scan(int pid, String pat, PrintStream out) throws IOException {
        El[] els = parse(pat);
        int L = 0; for (El e : els) L += e.w;
        if (L > 65536) throw new IllegalArgumentException("Pattern too long");
        int step = els[0].wild ? 1 : els[0].w;
        List<long[]> regs = new ArrayList<>(); long total = 0;
        try (BufferedReader m = new BufferedReader(new FileReader("/proc/" + pid + "/maps"))) {
            String ln;
            while ((ln = m.readLine()) != null) {
                String[] f = ln.split("\\s+", 6);
                if (f.length < 2 || f[1].charAt(0) != 'r') continue;
                String path = f.length > 5 ? f[5] : "";
                if (path.startsWith("/dev/") || path.startsWith("/system") || path.startsWith("/apex")
                        || path.startsWith("/vendor") || path.startsWith("[vv")) continue;
                int d = f[0].indexOf('-');
                long s = Long.parseUnsignedLong(f[0].substring(0, d), 16);
                long e = Long.parseUnsignedLong(f[0].substring(d + 1), 16);
                regs.add(new long[]{s, e}); total += e - s;
            }
        }
        byte[] buf = new byte[CH + L];
        ByteBuffer bb = ByteBuffer.wrap(buf).order(ByteOrder.LITTLE_ENDIAN);
        long count = 0, done = 0; int lastP = -1;
        try (RandomAccessFile raf = new RandomAccessFile("/proc/" + pid + "/mem", "r")) {
            for (long[] rg : regs) {
                long size = rg[1] - rg[0];
                for (long pos = 0; pos < size; pos += CH) {
                    int n = (int) Math.min((long) CH + L - 1, size - pos);
                    int lim = Math.min(CH, n - L + 1);
                    done += Math.min(CH, size - pos);
                    int pct = (int) (done * 100 / Math.max(total, 1));
                    if (pct != lastP) { lastP = pct; out.println("P " + pct); }
                    if (lim <= 0) continue;
                    try { raf.seek(rg[0] + pos); raf.readFully(buf, 0, n); } catch (IOException ex) { continue; }
                    for (int i = 0; i < lim; i += step) {
                        if (match(bb, i, els)) {
                            count++;
                            if (count <= MAXR) {
                                StringBuilder h = new StringBuilder();
                                for (int k = 0; k < Math.min(L, 32); k++) h.append(String.format("%02x", buf[i + k]));
                                out.println("R " + Long.toHexString(rg[0] + pos + i) + " " + h);
                            }
                        }
                    }
                }
            }
        }
        out.println("C " + count);
    }
}

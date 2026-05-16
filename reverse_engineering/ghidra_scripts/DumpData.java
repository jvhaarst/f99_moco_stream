//Dump bytes at specific addresses and find xrefs.
//@category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.*;
import java.io.*;

public class DumpData extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outPath = args.length > 0 ? args[0] : "/tmp/icap_data.txt";
        PrintWriter pw = new PrintWriter(new FileWriter(outPath));

        long[] addrs = {0x002fc824L, 0x002fc828L, 0x002fc82cL};
        Memory mem = currentProgram.getMemory();
        AddressFactory af = currentProgram.getAddressFactory();

        for (long va : addrs) {
            Address a = af.getDefaultAddressSpace().getAddress(va);
            pw.println("=== " + String.format("0x%08x", va) + " ===");
            try {
                byte[] buf = new byte[16];
                mem.getBytes(a, buf);
                StringBuilder hex = new StringBuilder();
                for (byte b : buf) hex.append(String.format("%02x ", b & 0xff));
                pw.println("  bytes: " + hex);
                pw.println("  initialized? " + mem.getBlock(a).isInitialized());
            } catch (Exception e) {
                pw.println("  ERROR: " + e.getMessage());
            }
            // xrefs to this address
            ReferenceManager rm = currentProgram.getReferenceManager();
            ReferenceIterator it = rm.getReferencesTo(a);
            while (it.hasNext()) {
                Reference r = it.next();
                pw.println("  xref from " + r.getFromAddress() + " type=" + r.getReferenceType());
            }
        }

        // Now decompile FUN_0005a9a4 (the cipher) and FUN_0005a720/FUN_0005a708 (PRNG)
        // and FUN_0005a8a8 (strdup wrapper probably) and FUN_0005b3c0 (packet queueing)
        long[] funAddrs = {0x0005a9a4L, 0x0005a720L, 0x0005a708L, 0x0005a8a8L, 0x0005b3c0L, 0x0005a8a0L, 0x0005a684L};
        ghidra.app.decompiler.DecompInterface ifc = new ghidra.app.decompiler.DecompInterface();
        ifc.setOptions(new ghidra.app.decompiler.DecompileOptions());
        ifc.setSimplificationStyle("decompile");
        ifc.openProgram(currentProgram);
        FunctionManager fm = currentProgram.getFunctionManager();
        for (long va : funAddrs) {
            Address a = af.getDefaultAddressSpace().getAddress(va);
            Function f = fm.getFunctionAt(a);
            if (f == null) f = fm.getFunctionContaining(a);
            if (f == null) {
                pw.println("//// no function at " + String.format("0x%08x", va));
                continue;
            }
            pw.println("//// " + f.getName() + " @ " + f.getEntryPoint());
            ghidra.app.decompiler.DecompileResults res = ifc.decompileFunction(f, 60, monitor);
            if (res != null && res.getDecompiledFunction() != null) {
                pw.println(res.getDecompiledFunction().getC());
            }
            pw.println();
        }

        pw.close();
        println("Wrote " + outPath);
    }
}

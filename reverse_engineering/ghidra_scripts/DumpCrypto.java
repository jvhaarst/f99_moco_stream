import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import java.io.*;
public class DumpCrypto extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        PrintWriter pw = new PrintWriter(new FileWriter(args[0]));
        DecompInterface ifc = new DecompInterface();
        ifc.setOptions(new DecompileOptions());
        ifc.setSimplificationStyle("decompile");
        ifc.openProgram(currentProgram);
        FunctionManager fm = currentProgram.getFunctionManager();
        long[] addrs = {0x0005a980L, 0x0005ab04L};
        for (long va : addrs) {
            Address a = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(va);
            ghidra.program.model.listing.Function f = fm.getFunctionAt(a);
            if (f == null) f = fm.getFunctionContaining(a);
            if (f == null) { pw.println("no fn at " + va); continue; }
            pw.println("//// " + f.getName() + " @ " + f.getEntryPoint());
            DecompileResults r = ifc.decompileFunction(f, 60, monitor);
            if (r != null && r.getDecompiledFunction() != null) pw.println(r.getDecompiledFunction().getC());
            pw.println();
        }
        pw.close(); println("wrote " + args[0]);
    }
}

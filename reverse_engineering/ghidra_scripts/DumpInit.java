import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import java.io.*;
public class DumpInit extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        PrintWriter pw = new PrintWriter(new FileWriter(args[0]));
        Memory mem = currentProgram.getMemory();
        AddressFactory af = currentProgram.getAddressFactory();
        // Check block at 0x2fc824
        Address bssA = af.getDefaultAddressSpace().getAddress(0x002fc824L);
        MemoryBlock blk = mem.getBlock(bssA);
        pw.println("Block at 0x2fc824: name="+blk.getName()+" initialized="+blk.isInitialized()+" start="+blk.getStart()+" end="+blk.getEnd());
        // Decompile FUN at 0x2fffc and FUN_0005d2d0
        DecompInterface ifc = new DecompInterface();
        ifc.setOptions(new DecompileOptions());
        ifc.setSimplificationStyle("decompile");
        ifc.openProgram(currentProgram);
        FunctionManager fm = currentProgram.getFunctionManager();
        long[] addrs = {0x0002fffcL, 0x0005d2d0L, 0x0005bb58L, 0x0005b110L};
        for (long va : addrs) {
            Address a = af.getDefaultAddressSpace().getAddress(va);
            Function f = fm.getFunctionContaining(a);
            if (f == null) {
                pw.println("//// no function containing "+String.format("0x%08x",va));
                continue;
            }
            pw.println("//// "+f.getName()+" @ "+f.getEntryPoint());
            DecompileResults res = ifc.decompileFunction(f, 60, monitor);
            if (res != null && res.getDecompiledFunction()!=null) {
                pw.println(res.getDecompiledFunction().getC());
            }
            pw.println();
        }
        pw.close();
        println("wrote "+args[0]);
    }
}

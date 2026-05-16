import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.util.*;
public class DumpStream extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        PrintWriter pw = new PrintWriter(new FileWriter(args[0]));
        DecompInterface ifc = new DecompInterface();
        ifc.setOptions(new DecompileOptions());
        ifc.setSimplificationStyle("decompile");
        ifc.openProgram(currentProgram);
        FunctionManager fm = currentProgram.getFunctionManager();
        SymbolTable st = currentProgram.getSymbolTable();
        AddressFactory af = currentProgram.getAddressFactory();
        long[] addrs = {
            0x00059c3cL, // stream.connect
            0x00059da8L, // stream.disconnect
            0x00059e2cL,
            0x00059ed0L,
            0x00059f74L,
            0x0005a0b8L,
            0x0005a1e4L,
            0x00059c00L, // strdup-like
            0x00056294L  // FUN_00056294 (used after add_icap_req in camera_play_video)
        };
        for (long va : addrs) {
            Address a = af.getDefaultAddressSpace().getAddress(va);
            Function f = fm.getFunctionAt(a);
            if (f == null) f = fm.getFunctionContaining(a);
            if (f == null) { pw.println("//// no function at "+String.format("0x%08x",va)); continue; }
            pw.println("//// "+f.getName()+" @ "+f.getEntryPoint()+" size="+f.getBody().getNumAddresses());
            DecompileResults res = ifc.decompileFunction(f, 60, monitor);
            if (res != null && res.getDecompiledFunction()!=null)
                pw.println(res.getDecompiledFunction().getC());
            pw.println();
        }
        // also find callers of create_camera_stream_of_connect_to_camera (0x0005a310)
        ReferenceManager rm = currentProgram.getReferenceManager();
        Address csta = af.getDefaultAddressSpace().getAddress(0x0005a310L);
        pw.println("//// Callers of create_camera_stream_of_connect_to_camera:");
        Set<Function> callers = new LinkedHashSet<>();
        ReferenceIterator it = rm.getReferencesTo(csta);
        while (it.hasNext()) {
            Reference r = it.next();
            Function cf = fm.getFunctionContaining(r.getFromAddress());
            if (cf != null) callers.add(cf);
        }
        for (Function cf : callers) {
            pw.println("//// "+cf.getName()+" @ "+cf.getEntryPoint()+" size="+cf.getBody().getNumAddresses());
            DecompileResults res = ifc.decompileFunction(cf, 60, monitor);
            if (res != null && res.getDecompiledFunction()!=null)
                pw.println(res.getDecompiledFunction().getC());
            pw.println();
        }
        // Also look for "FUN_00036438" the function called from JNI ConnectCameraByIP
        Address fa = af.getDefaultAddressSpace().getAddress(0x00036438L);
        Function f = fm.getFunctionContaining(fa);
        if (f != null) {
            pw.println("//// "+f.getName()+" @ "+f.getEntryPoint()+" size="+f.getBody().getNumAddresses());
            DecompileResults res = ifc.decompileFunction(f, 60, monitor);
            if (res != null && res.getDecompiledFunction()!=null)
                pw.println(res.getDecompiledFunction().getC());
            pw.println();
        }
        pw.close();
        println("wrote "+args[0]);
    }
}

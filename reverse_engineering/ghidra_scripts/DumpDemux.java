import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.util.*;
public class DumpDemux extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        PrintWriter pw = new PrintWriter(new FileWriter(args[0]));
        DecompInterface ifc = new DecompInterface();
        ifc.setOptions(new DecompileOptions());
        ifc.setSimplificationStyle("decompile");
        ifc.openProgram(currentProgram);
        FunctionManager fm = currentProgram.getFunctionManager();
        SymbolTable st = currentProgram.getSymbolTable();
        ReferenceManager rm = currentProgram.getReferenceManager();
        // Find callers of parse_icap_data_recved — the upstream demuxer
        Set<Function> seen = new LinkedHashSet<Function>();
        SymbolIterator it = st.getSymbols("parse_icap_data_recved");
        while (it.hasNext()) {
            Function tgt = fm.getFunctionAt(it.next().getAddress());
            if (tgt == null) continue;
            ReferenceIterator rit = rm.getReferencesTo(tgt.getEntryPoint());
            while (rit.hasNext()) {
                Function caller = fm.getFunctionContaining(rit.next().getFromAddress());
                if (caller != null) seen.add(caller);
            }
        }
        // Also follow one level up — the dispatcher might be 2-deep
        Set<Function> level2 = new LinkedHashSet<Function>(seen);
        for (Function f : seen) {
            ReferenceIterator rit = rm.getReferencesTo(f.getEntryPoint());
            while (rit.hasNext()) {
                Function caller = fm.getFunctionContaining(rit.next().getFromAddress());
                if (caller != null) level2.add(caller);
            }
        }
        for (Function f : level2) {
            pw.println("//// " + f.getName() + " @ " + f.getEntryPoint() + " size=" + f.getBody().getNumAddresses());
            DecompileResults res = ifc.decompileFunction(f, 90, monitor);
            if (res != null && res.getDecompiledFunction() != null) pw.println(res.getDecompiledFunction().getC());
            pw.println();
        }
        pw.close();
        println("wrote " + args[0]);
    }
}

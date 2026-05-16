import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.util.*;
public class FindAddIcapCallers extends GhidraScript {
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
        Function target = null;
        SymbolIterator it = st.getSymbols("add_icap_req");
        while (it.hasNext()) { Function f = fm.getFunctionAt(it.next().getAddress()); if (f != null) { target = f; break; } }
        if (target == null) { pw.println("add_icap_req not found"); pw.close(); return; }
        Set<Function> callers = new LinkedHashSet<Function>();
        ReferenceIterator rit = rm.getReferencesTo(target.getEntryPoint());
        while (rit.hasNext()) {
            Function caller = fm.getFunctionContaining(rit.next().getFromAddress());
            if (caller != null) callers.add(caller);
        }
        for (Function f : callers) {
            pw.println("//// " + f.getName() + " @ " + f.getEntryPoint() + " size=" + f.getBody().getNumAddresses());
            DecompileResults res = ifc.decompileFunction(f, 60, monitor);
            if (res != null && res.getDecompiledFunction() != null) pw.println(res.getDecompiledFunction().getC());
            pw.println();
        }
        pw.close();
        println("wrote " + args[0] + " with " + callers.size() + " callers");
    }
}

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.util.*;
public class DumpLoginPath extends GhidraScript {
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
        String[] wanted = {"parse_icap_login2_resp", "parse_icap_login1_resp", "icap_error_2_camera_error"};
        Set<Function> seen = new LinkedHashSet<Function>();
        for (String name : wanted) {
            SymbolIterator it = st.getSymbols(name);
            while (it.hasNext()) {
                Symbol s = it.next();
                Function f = fm.getFunctionAt(s.getAddress());
                if (f == null) continue;
                ReferenceIterator rit = rm.getReferencesTo(f.getEntryPoint());
                while (rit.hasNext()) {
                    Function caller = fm.getFunctionContaining(rit.next().getFromAddress());
                    if (caller != null) seen.add(caller);
                }
            }
        }
        for (Function f : seen) {
            pw.println("//// " + f.getName() + " @ " + f.getEntryPoint());
            DecompileResults res = ifc.decompileFunction(f, 60, monitor);
            if (res != null && res.getDecompiledFunction() != null) pw.println(res.getDecompiledFunction().getC());
            pw.println();
        }
        pw.close();
        println("wrote " + args[0]);
    }
}

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.util.*;
public class DumpUdp extends GhidraScript {
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
        // Find functions calling sendto/recvfrom/SO_BROADCAST/bind
        Set<Function> targets = new LinkedHashSet<>();
        String[] libcs = {"sendto","recvfrom","bind","setsockopt"};
        for (String name : libcs) {
            for (Symbol s : (Iterable<Symbol>)() -> st.getSymbols(name)) {
                ReferenceIterator it = currentProgram.getReferenceManager().getReferencesTo(s.getAddress());
                while (it.hasNext()) {
                    Function cf = fm.getFunctionContaining(it.next().getFromAddress());
                    if (cf != null) targets.add(cf);
                }
            }
        }
        for (Function f : targets) {
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

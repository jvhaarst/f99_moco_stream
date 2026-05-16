import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.LinkedHashSet;
import java.util.Set;

public class FindSendto extends GhidraScript {
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
        String[] names = {"sendto","recvfrom","bind","socket"};
        Set<Function> callers = new LinkedHashSet<Function>();
        for (int i = 0; i < names.length; i++) {
            String name = names[i];
            pw.println("=== xrefs to " + name + " ===");
            SymbolIterator sit = st.getSymbols(name);
            while (sit.hasNext()) {
                Symbol s = sit.next();
                pw.println("  symbol at " + s.getAddress() + " type=" + s.getSymbolType());
                ReferenceIterator it = rm.getReferencesTo(s.getAddress());
                int n = 0;
                while (it.hasNext()) {
                    Reference r = it.next();
                    Function cf = fm.getFunctionContaining(r.getFromAddress());
                    String tag = cf == null ? "?" : (cf.getName() + "@" + cf.getEntryPoint());
                    pw.println("    from " + r.getFromAddress() + " in " + tag);
                    if (cf != null && (name.equals("sendto") || name.equals("recvfrom"))) {
                        callers.add(cf);
                    }
                    n++;
                    if (n > 50) { pw.println("    ..."); break; }
                }
            }
        }
        for (Function f : callers) {
            pw.println();
            pw.println("//// "+f.getName()+" @ "+f.getEntryPoint()+" size="+f.getBody().getNumAddresses());
            DecompileResults res = ifc.decompileFunction(f, 90, monitor);
            if (res != null && res.getDecompiledFunction()!=null) {
                pw.println(res.getDecompiledFunction().getC());
            }
        }
        pw.close();
        println("wrote "+args[0]+" with " + callers.size() + " callers");
    }
}

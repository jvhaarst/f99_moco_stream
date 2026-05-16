import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.LinkedHashSet;
import java.util.Set;

public class FindSendto2 extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        PrintWriter pw = new PrintWriter(new FileWriter(args[0]));
        DecompInterface ifc = new DecompInterface();
        ifc.setOptions(new DecompileOptions());
        ifc.setSimplificationStyle("decompile");
        ifc.openProgram(currentProgram);
        FunctionManager fm = currentProgram.getFunctionManager();
        ReferenceManager rm = currentProgram.getReferenceManager();

        String[] thunkNames = {"sendto","recvfrom","bind","socket","setsockopt","gethostbyname","inet_addr"};
        Set<Function> callers = new LinkedHashSet<Function>();
        for (String name : thunkNames) {
            pw.println("=== " + name + " (PLT thunk) ===");
            // Find the THUNK function that calls EXTERNAL sendto
            Function thunk = null;
            for (Function f : fm.getFunctions(true)) {
                if (f.isThunk() && f.getName().equals(name)) {
                    thunk = f;
                    pw.println("  PLT thunk at " + f.getEntryPoint());
                    break;
                }
            }
            if (thunk == null) { pw.println("  no thunk found"); continue; }
            ReferenceIterator it = rm.getReferencesTo(thunk.getEntryPoint());
            int n = 0;
            while (it.hasNext()) {
                Reference r = it.next();
                Function cf = fm.getFunctionContaining(r.getFromAddress());
                String tag = cf == null ? "?" : (cf.getName() + "@" + cf.getEntryPoint());
                pw.println("    from " + r.getFromAddress() + " in " + tag);
                if (cf != null && (name.equals("sendto") || name.equals("recvfrom"))) {
                    callers.add(cf);
                }
                if (++n > 80) { pw.println("    ..."); break; }
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
        println("wrote " + args[0] + " with " + callers.size() + " callers");
    }
}

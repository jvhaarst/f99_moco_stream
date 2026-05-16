import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.util.*;
public class DumpConnect extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        PrintWriter pw = new PrintWriter(new FileWriter(args[0]));
        DecompInterface ifc = new DecompInterface();
        ifc.setOptions(new DecompileOptions());
        ifc.setSimplificationStyle("decompile");
        ifc.openProgram(currentProgram);
        SymbolTable st = currentProgram.getSymbolTable();
        FunctionManager fm = currentProgram.getFunctionManager();
        Set<String> wanted = new LinkedHashSet<>(Arrays.asList(
            "Java_com_sosocam_rcipcam3x_RCIPCam3X_ConnectCameraByIP",
            "Java_com_sosocam_rcipcam3x_RCIPCam3X_ConnectCameraByReeCam",
            "Java_com_sosocam_rcipcam3x_RCIPCam3X_HttpClientGet",
            "http_client_get",
            "socket_connect",
            "parse_url"
        ));
        for (String name : wanted) {
            SymbolIterator it = st.getSymbols(name);
            Function f = null;
            while (it.hasNext()) {
                Symbol s = it.next();
                Function cand = fm.getFunctionAt(s.getAddress());
                if (cand != null) { f = cand; break; }
            }
            if (f == null) { pw.println("//// NOT FOUND: "+name); continue; }
            pw.println("//// "+name+" @ "+f.getEntryPoint());
            DecompileResults res = ifc.decompileFunction(f, 60, monitor);
            if (res != null && res.getDecompiledFunction()!=null)
                pw.println(res.getDecompiledFunction().getC());
            pw.println();
        }
        // Also: find functions that call create_icap_context — those are the
        // "open connection" callers we want to see.
        Function ctxFn = fm.getFunctionAt(currentProgram.getAddressFactory()
            .getDefaultAddressSpace().getAddress(0x0005acacL));
        pw.println("//// Callers of create_icap_context:");
        ReferenceManager rm = currentProgram.getReferenceManager();
        ReferenceIterator rit = rm.getReferencesTo(ctxFn.getEntryPoint());
        Set<Function> callers = new LinkedHashSet<>();
        while (rit.hasNext()) {
            Reference r = rit.next();
            Function cf = fm.getFunctionContaining(r.getFromAddress());
            if (cf != null) callers.add(cf);
        }
        for (Function cf : callers) {
            pw.println("//// "+cf.getName()+" @ "+cf.getEntryPoint());
            DecompileResults res = ifc.decompileFunction(cf, 60, monitor);
            if (res != null && res.getDecompiledFunction()!=null)
                pw.println(res.getDecompiledFunction().getC());
            pw.println();
        }
        pw.close();
        println("wrote "+args[0]);
    }
}

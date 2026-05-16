import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.util.*;
public class DumpCameraConnect extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        PrintWriter pw = new PrintWriter(new FileWriter(args[0]));
        DecompInterface ifc = new DecompInterface();
        ifc.setOptions(new DecompileOptions());
        ifc.setSimplificationStyle("decompile");
        ifc.openProgram(currentProgram);
        SymbolTable st = currentProgram.getSymbolTable();
        FunctionManager fm = currentProgram.getFunctionManager();
        String[] wanted = {
            "camera_connect",
            "camera_disconnect",
            "connect_to_camera",
            "destroy_camera_stream_of_connect_to_camera",
            "create_camera_stream_of_connect_to_camera",
            "camera_play_video",
            "camera_get_properties",
        };
        for (String name : wanted) {
            SymbolIterator it = st.getSymbols(name);
            Function f = null;
            while (it.hasNext()) {
                Symbol s = it.next();
                Function cand = fm.getFunctionAt(s.getAddress());
                if (cand != null) { f = cand; break; }
            }
            if (f == null) { pw.println("//// NOT FOUND: "+name); continue; }
            pw.println("//// "+name+" @ "+f.getEntryPoint()+" size="+f.getBody().getNumAddresses());
            DecompileResults res = ifc.decompileFunction(f, 60, monitor);
            if (res != null && res.getDecompiledFunction()!=null)
                pw.println(res.getDecompiledFunction().getC());
            pw.println();
        }
        // Also enumerate all functions whose name contains "camera_"
        pw.println("//// All camera_* functions:");
        for (Function f : fm.getFunctions(true)) {
            if (f.getName().startsWith("camera_") || f.getName().contains("connect_to_camera")) {
                pw.println("//   "+f.getName()+" @ "+f.getEntryPoint()+" size="+f.getBody().getNumAddresses());
            }
        }
        pw.close();
        println("wrote "+args[0]);
    }
}

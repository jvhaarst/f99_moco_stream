import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.util.*;
public class DumpDiscover extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        PrintWriter pw = new PrintWriter(new FileWriter(args[0]));
        DecompInterface ifc = new DecompInterface();
        ifc.setOptions(new DecompileOptions());
        ifc.setSimplificationStyle("decompile");
        ifc.openProgram(currentProgram);
        FunctionManager fm = currentProgram.getFunctionManager();
        SymbolTable st = currentProgram.getSymbolTable();
        String[] wanted = {
            "Java_com_sosocam_rcipcam3x_RCIPCam3X_StartDiscoverCameras",
            "handle_msg_start_discover_cameras",
            "search_cameras",
            "search_request_new",
            "search_request_finished",
            "parse_search_resp",
            "packet_search_respone_proc",
            "p_broadcast_udp_send",
            "_search_camera_addr",
            "_get_camera_id"
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

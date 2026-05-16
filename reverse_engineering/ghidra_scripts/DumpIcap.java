//Dump decompiled C for ICAP-related functions to a file.
//@category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.util.*;

public class DumpIcap extends GhidraScript {
    @Override
    public void run() throws Exception {
        DecompInterface ifc = new DecompInterface();
        DecompileOptions opts = new DecompileOptions();
        ifc.setOptions(opts);
        ifc.setSimplificationStyle("decompile");
        ifc.openProgram(currentProgram);

        // Pick up output path from script args (set by analyzeHeadless -scriptArgs)
        String[] args = getScriptArgs();
        String outPath = args.length > 0 ? args[0] : "/tmp/icap_dump.txt";
        PrintWriter pw = new PrintWriter(new FileWriter(outPath));

        SymbolTable st = currentProgram.getSymbolTable();
        FunctionManager fm = currentProgram.getFunctionManager();

        // Collect target function names
        Set<String> wanted = new LinkedHashSet<>(Arrays.asList(
            "create_icap_context",
            "destroy_icap_context",
            "close_icap_context",
            "add_icap_req",
            "add_icap_login2_req",
            "add_icap_ptz_control_req",
            "add_icap_play_record_req",
            "add_icap_speak_data",
            "add_icap_write_serial_data",
            "parse_icap_login1_resp",
            "parse_icap_login2_resp",
            "parse_icap_video_data",
            "parse_icap_video2_data",
            "parse_icap_audio_data",
            "parse_icap_data_recved",
            "parse_icap_play_record_notify",
            "parse_icap_result_class_resp",
            "parse_icap_result_str_class_resp",
            "parse_icap_serial_data",
            "parse_icap_write_serial_resp",
            "get_icap_packet_to_send",
            "put_icap_data_recved",
            "icap_error_2_camera_error"
        ));

        for (String name : wanted) {
            SymbolIterator it = st.getSymbols(name);
            Function f = null;
            while (it.hasNext()) {
                Symbol s = it.next();
                Function cand = fm.getFunctionAt(s.getAddress());
                if (cand != null) { f = cand; break; }
            }
            if (f == null) {
                pw.println("//// NOT FOUND: " + name);
                pw.println();
                continue;
            }
            pw.println("//// " + name + " @ " + f.getEntryPoint() + " size=" + f.getBody().getNumAddresses());
            DecompileResults res = ifc.decompileFunction(f, 60, monitor);
            if (res == null || res.getDecompiledFunction() == null) {
                pw.println("// decompile failed: " + (res != null ? res.getErrorMessage() : "null"));
            } else {
                pw.println(res.getDecompiledFunction().getC());
            }
            pw.println();
        }

        // Also: list any other functions whose name contains "icap" that we missed
        pw.println("//// OTHER icap-named functions:");
        for (Function f : fm.getFunctions(true)) {
            String n = f.getName();
            if (n.toLowerCase().contains("icap") && !wanted.contains(n)) {
                pw.println("//   " + n + " @ " + f.getEntryPoint());
            }
        }

        pw.close();
        println("Dumped to " + outPath);
    }
}

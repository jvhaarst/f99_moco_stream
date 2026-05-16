import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;
public class DumpMoqoConn extends GhidraScript {
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
            "Java_com_sosocam_rcipcam3x_RCIPCam3X_ConnectCameraByIP",
            "create_camera",
            "create_icap_context",
            "InitBlowfish",
        };
        for (String name : wanted) {
            SymbolIterator it = st.getSymbols(name);
            while (it.hasNext()) {
                Function f = fm.getFunctionAt(it.next().getAddress());
                if (f != null) {
                    pw.println("//// " + f.getName() + " @ " + f.getEntryPoint() + " size=" + f.getBody().getNumAddresses());
                    DecompileResults res = ifc.decompileFunction(f, 60, monitor);
                    if (res != null && res.getDecompiledFunction() != null) pw.println(res.getDecompiledFunction().getC());
                    pw.println();
                    break;
                }
            }
        }
        pw.close();
        println("wrote " + args[0]);
    }
}

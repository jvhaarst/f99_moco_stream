import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;
public class DumpMoqoConnect extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        PrintWriter pw = new PrintWriter(new FileWriter(args[0]));
        DecompInterface ifc = new DecompInterface();
        ifc.setOptions(new DecompileOptions());
        ifc.setSimplificationStyle("decompile");
        ifc.openProgram(currentProgram);
        FunctionManager fm = currentProgram.getFunctionManager();
        SymbolTable st = currentProgram.getSymbolTable();
        String[] wanted = {"camera_connect", "stream_on_status_changed", "create_camera", "stream_can_write", "stream_can_read"};
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

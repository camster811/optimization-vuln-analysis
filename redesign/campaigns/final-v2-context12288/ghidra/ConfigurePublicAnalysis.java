// @category Analysis
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;

/** Never recover removed debug information from host build-id caches or symbol servers. */
public class ConfigurePublicAnalysis extends GhidraScript {
    @Override
    public void run() throws Exception {
        var options = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES);
        // Options registered by available analyzers; do not invent an unknown option silently.
        for (String name : options.getOptionNames()) {
            if (name.equals("DWARF") || name.equals("PDB") || name.equals("PDB Universal")) {
                options.setBoolean(name, false);
                println("Disabled external debug analyzer: " + name);
            }
        }
        if (options.getBoolean("DWARF", true)) {
            throw new IllegalStateException("DWARF analysis must be disabled");
        }
    }
}

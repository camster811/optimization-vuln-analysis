// @category Analysis
// @importpackage com.google.gson

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Reference;

/** Address-rooted export. Inputs are public ELF + entry + generic limits, never oracle facts. */
public class ExtractBundle extends HeadlessScript {
    private JsonObject bundle;
    private JsonObject completeness;
    private JsonArray omissions;
    private final TreeMap<Address, TreeSet<Address>> dataReferences = new TreeMap<>();
    private final TreeMap<Address, Function> pending = new TreeMap<>();
    private final Set<Address> visited = new HashSet<>();
    private int instructionCount = 0;
    private int maxFunctions, maxInstructions, maxData, perData, unknownData, timeout;

    private static String hex(Address address) {
        return "0x" + Long.toUnsignedString(address.getOffset(), 16);
    }

    private static String bytes(byte[] value) {
        StringBuilder out = new StringBuilder();
        for (byte item : value) out.append(String.format("%02x", item & 255));
        return out.toString();
    }

    private static String stringPrefix(byte[] raw) {
        StringBuilder text = new StringBuilder();
        for (byte item : raw) {
            int value = item & 255;
            if (value == 0) return text.length() == 0 ? null : text.toString();
            if (!(value >= 32 && value <= 126) && value != 9 && value != 10 && value != 13) return null;
            text.append((char)value);
        }
        return null;
    }

    private void omit(String reason, Address address, boolean budget) {
        JsonObject item = new JsonObject();
        item.addProperty("reason", reason);
        if (address == null) item.add("address", JsonNull.INSTANCE);
        else item.addProperty("address", hex(address));
        omissions.add(item);
        if (budget || !bundle.get("status").getAsString().equals("context_unavailable")) {
            bundle.addProperty("status", budget ? "context_unavailable" : "extraction_unavailable");
        }
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 9) throw new IllegalArgumentException("Expected entry, output and seven limits");
        Path output = Path.of(args[1]);
        bundle = new JsonObject();
        bundle.addProperty("schema_version", 2);
        bundle.addProperty("architecture", "x86-64");
        bundle.addProperty("policy_id", "entry-closure-v1");
        bundle.addProperty("status", "available");
        bundle.addProperty("entry_address", args[0]);
        JsonArray assumptions = new JsonArray();
        assumptions.add("One invocation of the localized entry; no concurrent mutation or library interposition.");
        assumptions.add("System V x86-64 ABI and ordinary libc allocation, string and output semantics.");
        assumptions.add("Decompiler types and referenced-data windows are uncertain recovery, not proven object bounds.");
        bundle.add("assumptions", assumptions);
        for (String key : List.of("functions", "calls", "data", "unresolved_transfers")) {
            bundle.add(key, new JsonArray());
        }
        completeness = new JsonObject();
        completeness.addProperty("traversal", "complete");
        completeness.addProperty("data", "complete");
        completeness.addProperty("decompilation", "complete");
        completeness.addProperty("external_bodies", "excluded");
        completeness.addProperty("localization", "private_entry_address");
        omissions = new JsonArray();
        completeness.add("omissions", omissions);
        bundle.add("completeness", completeness);
        try {
            timeout = Integer.parseInt(args[2]);
            maxFunctions = Integer.parseInt(args[3]);
            maxInstructions = Integer.parseInt(args[4]);
            maxData = Integer.parseInt(args[5]);
            perData = Integer.parseInt(args[6]);
            unknownData = Integer.parseInt(args[7]);
            boolean allowAssembly = args[8].equals("true");
            if (currentProgram.getOptions(Program.ANALYSIS_PROPERTIES).getBoolean("DWARF", true)) {
                throw new IllegalStateException("External debug recovery must be disabled before analysis");
            }
            if (Math.min(Math.min(timeout, maxFunctions), Math.min(maxInstructions, maxData)) <= 0 ||
                    perData <= 0 || unknownData <= 0) throw new IllegalArgumentException();
            if (!currentProgram.getLanguageID().toString().equals("x86:LE:64:default") ||
                    !currentProgram.getCompilerSpec().getCompilerSpecID().toString().equals("gcc")) {
                throw new IllegalArgumentException();
            }
            Address entry = currentProgram.getAddressFactory().getDefaultAddressSpace()
                .getAddress(Long.parseUnsignedLong(args[0].substring(2), 16));
            Function root = currentProgram.getFunctionManager().getFunctionContaining(entry);
            if (analysisTimeoutOccurred()) {
                completeness.addProperty("traversal", "incomplete");
                omit("analysis_timeout", null, false);
            }
            else if (root == null || boundary(root, entry)) {
                completeness.addProperty("traversal", "incomplete");
                omit("entry_function_not_recovered", entry, false);
            }
            else {
                pending.put(root.getEntryPoint(), root);
                while (!pending.isEmpty()) {
                    monitor.checkCancelled();
                    Function function = pending.pollFirstEntry().getValue();
                    if (!visited.add(function.getEntryPoint())) continue;
                    if (bundle.getAsJsonArray("functions").size() >= maxFunctions) {
                        completeness.addProperty("traversal", "incomplete");
                        omit("function_limit", function.getEntryPoint(), true);
                        break;
                    }
                    exportFunction(function, allowAssembly);
                    if (instructionCount > maxInstructions) break;
                }
                exportData();
            }
        }
        catch (Exception exception) {
            completeness.addProperty("traversal", "incomplete");
            // Do not serialize exception messages, which can contain private paths.
            omit(monitor.isCancelled() ? "analysis_cancelled" : "export_failed", null, false);
        }
        Files.createDirectories(output.getParent());
        Files.writeString(output, new GsonBuilder().disableHtmlEscaping().serializeNulls()
            .create().toJson(bundle) + "\n", StandardCharsets.UTF_8);
    }

    private boolean boundary(Function function, Address destination) {
        if (function != null && function.isExternal()) return true;
        MemoryBlock block = currentProgram.getMemory().getBlock(destination);
        if (block != null && (block.getName().equals(".plt") || block.getName().startsWith(".plt."))) return true;
        return false;
    }

    private String targetName(Function function, Address destination) {
        if (function == null) return hex(destination);
        if (function.isThunk() && boundary(function, destination)) {
            Function resolved = function.getThunkedFunction(true);
            if (resolved != null) return resolved.getName();
        }
        return function.getName();
    }

    private void exportFunction(Function function, boolean allowAssembly) throws Exception {
        JsonObject item = new JsonObject();
        item.addProperty("entry", hex(function.getEntryPoint()));
        item.addProperty("name", function.getName());
        item.addProperty("name_origin", function.getSymbol().getSource().toString().toLowerCase());
        JsonArray ranges = new JsonArray();
        AddressRangeIterator iterator = function.getBody().getAddressRanges(true);
        while (iterator.hasNext()) {
            AddressRange range = iterator.next();
            JsonObject region = new JsonObject();
            region.addProperty("start", hex(range.getMinAddress()));
            region.addProperty("end", hex(range.getMaxAddress().next()));
            ranges.add(region);
        }
        item.add("ranges", ranges);
        JsonArray instructions = new JsonArray();
        item.add("instructions", instructions);
        bundle.getAsJsonArray("functions").add(item);
        InstructionIterator listing = currentProgram.getListing().getInstructions(function.getBody(), true);
        while (listing.hasNext()) {
            monitor.checkCancelled();
            Instruction instruction = listing.next();
            if (++instructionCount > maxInstructions) {
                completeness.addProperty("traversal", "incomplete");
                omit("instruction_limit", instruction.getAddress(), true);
                break;
            }
            JsonObject ins = new JsonObject();
            ins.addProperty("address", hex(instruction.getAddress()));
            ins.addProperty("size", instruction.getLength());
            ins.addProperty("bytes", bytes(instruction.getBytes()));
            ins.addProperty("mnemonic", instruction.getMnemonicString());
            List<String> operands = new ArrayList<>();
            for (int n = 0; n < instruction.getNumOperands(); n++) {
                operands.add(instruction.getDefaultOperandRepresentation(n));
            }
            ins.addProperty("operands", String.join(",", operands));
            instructions.add(ins);
            exportFlows(function, instruction);
            for (Reference reference : instruction.getReferencesFrom()) {
                Address target = reference.getToAddress();
                MemoryBlock block = currentProgram.getMemory().getBlock(target);
                if (reference.getReferenceType().isData() && target.isMemoryAddress()) {
                    if (block == null) {
                        completeness.addProperty("data", "incomplete");
                        omit("data_reference_unavailable", target, false);
                    }
                    else if (!block.isExecute() || currentProgram.getListing().getInstructionContaining(target) == null) {
                        dataReferences.computeIfAbsent(target, ignored -> new TreeSet<>()).add(instruction.getAddress());
                    }
                }
            }
        }
        JsonObject decompilation = new JsonObject();
        decompilation.addProperty("status", "error");
        decompilation.addProperty("text", "");
        DecompInterface decompiler = new DecompInterface();
        try {
            if (decompiler.openProgram(currentProgram)) {
                DecompileResults result = decompiler.decompileFunction(function, timeout, monitor);
                if (result != null && result.decompileCompleted() && result.getDecompiledFunction() != null) {
                    decompilation.addProperty("status", "ok");
                    decompilation.addProperty("text", result.getDecompiledFunction().getC()
                        .replace("\r\n", "\n").replace('\r', '\n'));
                }
                else if (result != null && result.isTimedOut()) decompilation.addProperty("status", "timeout");
                else if (result != null && result.isCancelled()) decompilation.addProperty("status", "cancelled");
            }
        }
        finally { decompiler.dispose(); }
        item.add("decompilation", decompilation);
        if (!decompilation.get("status").getAsString().equals("ok")) {
            completeness.addProperty("decompilation", "incomplete");
            if (!allowAssembly) omit("decompilation_failed", function.getEntryPoint(), false);
        }
    }

    private void exportFlows(Function caller, Instruction instruction) {
        FlowType flow = instruction.getFlowType();
        // Ghidra's call-return analysis can override a native JMP's flow type to CALL.
        // Keep the emitted transfer kind, including application wrappers in .text.
        boolean jump = flow.isJump() || instruction.getMnemonicString().toUpperCase().startsWith("J");
        if (!(flow.isCall() || jump)) return;
        Address[] destinations = instruction.getFlows();
        if (flow.isComputed() || destinations.length == 0) {
            JsonObject unresolved = new JsonObject();
            unresolved.addProperty("caller", hex(caller.getEntryPoint()));
            unresolved.addProperty("site", hex(instruction.getAddress()));
            unresolved.addProperty("kind", jump ? "jump" : "call");
            unresolved.addProperty("reason", "indirect_transfer");
            bundle.getAsJsonArray("unresolved_transfers").add(unresolved);
            completeness.addProperty("traversal", "incomplete");
            omit("indirect_transfer", instruction.getAddress(), false);
            return;
        }
        TreeSet<Address> sorted = new TreeSet<>(List.of(destinations));
        for (Address destination : sorted) {
            if (jump && caller.getBody().contains(destination)) continue;
            Function target = currentProgram.getFunctionManager().getFunctionContaining(destination);
            boolean external = boundary(target, destination);
            JsonObject edge = new JsonObject();
            edge.addProperty("caller", hex(caller.getEntryPoint()));
            edge.addProperty("site", hex(instruction.getAddress()));
            edge.addProperty("target_address", hex(destination));
            edge.addProperty("target_name", targetName(target, destination));
            edge.addProperty("kind", jump ? "tail" : "call");
            edge.addProperty("resolution", external ? "external" : target != null ? "application" : "unresolved");
            if (target != null && !external) {
                edge.addProperty("target_entry", hex(target.getEntryPoint()));
                pending.put(target.getEntryPoint(), target);
            }
            else edge.add("target_entry", JsonNull.INSTANCE);
            bundle.getAsJsonArray("calls").add(edge);
            if (!external && target == null) {
                JsonObject unresolved = new JsonObject();
                unresolved.addProperty("caller", hex(caller.getEntryPoint()));
                unresolved.addProperty("site", hex(instruction.getAddress()));
                unresolved.addProperty("kind", jump ? "jump" : "call");
                unresolved.addProperty("reason", "target_function_not_recovered");
                bundle.getAsJsonArray("unresolved_transfers").add(unresolved);
                completeness.addProperty("traversal", "incomplete");
                omit("target_function_not_recovered", instruction.getAddress(), false);
            }
        }
    }

    private void exportData() throws Exception {
        int total = 0;
        for (Map.Entry<Address, TreeSet<Address>> reference : dataReferences.entrySet()) {
            monitor.checkCancelled();
            Address address = reference.getKey();
            MemoryBlock block = currentProgram.getMemory().getBlock(address);
            Data recovered = currentProgram.getListing().getDefinedDataContaining(address);
            boolean known = recovered != null && !recovered.getDataType().getName().startsWith("undefined");
            long extent = known ? recovered.getMaxAddress().subtract(address) + 1 : unknownData;
            long blockRemaining = block.getEnd().subtract(address) + 1;
            int length = (int)Math.min(Math.min(extent, perData), blockRemaining);
            if (total + length > maxData) {
                completeness.addProperty("data", "incomplete");
                omit("data_total_limit", address, true);
                break;
            }
            total += length;
            byte[] raw = new byte[length];
            if (block.isInitialized()) currentProgram.getMemory().getBytes(address, raw);
            JsonObject item = new JsonObject();
            item.addProperty("address", hex(address));
            item.addProperty("bytes", bytes(raw));
            String prefix = stringPrefix(raw);
            if (prefix == null) item.add("string_prefix", JsonNull.INSTANCE);
            else item.addProperty("string_prefix", prefix);
            item.addProperty("size", length);
            item.addProperty("writable", block.isWrite());
            item.addProperty("storage", block.isInitialized() ? "initialized" : "zero_filled");
            item.addProperty("extent_status", known ? "recovered_type_extent" : "unknown_window");
            item.addProperty("recovered_type", known ? recovered.getDataType().getDisplayName() : "unknown");
            item.addProperty("interpretation", "uncertain_binary_recovery_not_an_object_bound");
            JsonArray sites = new JsonArray();
            for (Address site : reference.getValue()) sites.add(hex(site));
            item.add("references", sites);
            item.addProperty("truncated", extent > length);
            bundle.getAsJsonArray("data").add(item);
            if (extent > length) {
                completeness.addProperty("data", "incomplete");
                omit("data_reference_limit", address, true);
            }
            else if (!known && !completeness.get("data").getAsString().equals("incomplete")) {
                completeness.addProperty("data", "uncertain");
            }
        }
    }
}

// @category Analysis
// @importpackage com.google.gson

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.TreeSet;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.CancelledException;

/**
 * Arguments: hexadecimal target address, output JSON path, positive timeout seconds.
 *
 * The function end is exclusive: one byte beyond the highest body address.
 * Disjoint function bodies are rejected: the flat instruction schema has no
 * range boundaries. Calls includes direct calls and direct tail
 * jumps outside the function body. Local branches and indirect transfers are
 * omitted. Thunks are resolved to their existing names.
 *
 * Success has exactly the documented record fields. Errors additionally have
 * error.code and error.message. An unresolved function is null; decompilation
 * has an empty text and status not_run, error, timeout, or cancelled. Error
 * messages are fixed strings so paths and other private metadata cannot leak
 * through exception diagnostics. I/O failures propagate to the script runner.
 */
public class ExtractFunction extends GhidraScript {
    private static final Gson JSON = new GsonBuilder()
        .disableHtmlEscaping().serializeNulls().setPrettyPrinting().create();

    private record DirectFlow(Address address, Address destination, String target) {}

    @Override
    public void run() throws Exception {
        String[] arguments = getScriptArgs();
        if (arguments.length < 2 || arguments[1].isBlank()) {
            // There is no destination at which a structured record can be written.
            throw new IllegalArgumentException(
                "Expected target address, output JSON path, and timeout seconds");
        }
        Path output = Path.of(arguments[1]).toAbsolutePath().normalize();
        JsonObject record = emptyRecord();
        try {
            extract(arguments, record);
        }
        catch (CancelledException exception) {
            fail(record, "cancelled", "Function extraction was cancelled.", "cancelled");
        }
        catch (RuntimeException exception) {
            fail(record, "extraction_failed", "Function extraction failed.", "error");
        }
        writeRecord(output, record);
    }

    private JsonObject emptyRecord() {
        JsonObject record = new JsonObject();
        record.addProperty("schema_version", 1);
        record.add("architecture", JsonNull.INSTANCE);
        record.add("function", JsonNull.INSTANCE);
        record.add("instructions", new JsonArray());
        record.add("calls", new JsonArray());
        record.add("decompilation", decompilation("not_run", ""));
        return record;
    }

    private void extract(String[] arguments, JsonObject record) throws CancelledException {
        if (arguments.length != 3 || !arguments[0].matches("(?i)(?:0x)?[0-9a-f]{1,16}")) {
            fail(record, "invalid_arguments", "Expected a hexadecimal address and timeout seconds.",
                "not_run");
            return;
        }
        int timeout;
        try {
            timeout = Integer.parseInt(arguments[2]);
            if (timeout <= 0) {
                throw new NumberFormatException();
            }
        }
        catch (NumberFormatException exception) {
            fail(record, "invalid_arguments", "Decompiler timeout must be a positive integer.",
                "not_run");
            return;
        }
        if (currentProgram == null) {
            fail(record, "no_program", "No program is open.", "not_run");
            return;
        }
        if (!currentProgram.getLanguageID().toString().startsWith("x86:LE:64:")) {
            fail(record, "unsupported_architecture", "Expected an x86-64 program.", "not_run");
            return;
        }
        record.addProperty("architecture", "x86-64");
        if (!currentProgram.getCompilerSpec().getCompilerSpecID().toString().equals("gcc")) {
            fail(record, "unsupported_compiler_spec", "Expected the GCC/System V compiler specification.",
                "not_run");
            return;
        }
        String hex = arguments[0].replaceFirst("(?i)^0x", "");
        Address address = currentProgram.getAddressFactory().getDefaultAddressSpace()
            .getAddress(Long.parseUnsignedLong(hex, 16));
        Function function = currentProgram.getFunctionManager().getFunctionContaining(address);
        if (function == null) {
            fail(record, "function_not_found", "No function contains the requested address.",
                "not_run");
            return;
        }
        if (function.getBody().getNumAddressRanges() != 1) {
            fail(record, "discontiguous_function_body",
                "Function body must contain exactly one address range.", "not_run");
            return;
        }

        Address end = function.getBody().getMaxAddress().next();
        if (end == null) {
            fail(record, "invalid_function_bounds", "Function end cannot be represented.", "not_run");
            return;
        }
        JsonObject description = new JsonObject();
        description.addProperty("name", function.getName());
        description.addProperty("entry", hex(function.getEntryPoint()));
        description.addProperty("end", hex(end));
        record.add("function", description);

        List<AddressRange> ranges = new ArrayList<>();
        AddressRangeIterator rangeIterator = function.getBody().getAddressRanges(true);
        while (rangeIterator.hasNext()) {
            ranges.add(rangeIterator.next());
        }
        ranges.sort(Comparator.comparing(AddressRange::getMinAddress));
        List<DirectFlow> flows = new ArrayList<>();
        JsonArray instructions = record.getAsJsonArray("instructions");
        for (AddressRange range : ranges) {
            InstructionIterator iterator = currentProgram.getListing().getInstructions(
                new AddressSet(range.getMinAddress(), range.getMaxAddress()), true);
            while (iterator.hasNext()) {
                monitor.checkCancelled();
                Instruction instruction = iterator.next();
                JsonObject item = new JsonObject();
                item.addProperty("address", hex(instruction.getAddress()));
                item.addProperty("mnemonic", instruction.getMnemonicString());
                List<String> operands = new ArrayList<>();
                for (int index = 0; index < instruction.getNumOperands(); index++) {
                    operands.add(instruction.getDefaultOperandRepresentation(index));
                }
                item.addProperty("operands", String.join(",", operands));
                instructions.add(item);
                collectDirectFlows(function, instruction, flows);
            }
        }
        flows.sort(Comparator.comparing(DirectFlow::address).thenComparing(DirectFlow::destination));
        JsonArray calls = record.getAsJsonArray("calls");
        for (DirectFlow flow : flows) {
            JsonObject item = new JsonObject();
            item.addProperty("address", hex(flow.address()));
            item.addProperty("target", flow.target());
            calls.add(item);
        }
        decompile(function, timeout, record);
    }

    private void collectDirectFlows(Function function, Instruction instruction, List<DirectFlow> flows) {
        FlowType type = instruction.getFlowType();
        if (type.isComputed() || !(type.isCall() || type.isJump())) {
            return;
        }
        Address[] destinations = instruction.getFlows();
        if (destinations == null) {
            return;
        }
        TreeSet<Address> sorted = new TreeSet<>();
        for (Address destination : destinations) {
            if (destination != null && destination.isMemoryAddress()) {
                sorted.add(destination);
            }
        }
        for (Address destination : sorted) {
            // Jumps within this body remain instructions, not invocations.
            if (type.isJump() && function.getBody().contains(destination)) {
                continue;
            }
            flows.add(new DirectFlow(instruction.getAddress(), destination, targetName(destination)));
        }
    }

    private String targetName(Address destination) {
        Function target = currentProgram.getFunctionManager().getFunctionAt(destination);
        if (target != null) {
            if (target.isThunk()) {
                Function resolved = target.getThunkedFunction(true);
                if (resolved != null) {
                    target = resolved;
                }
            }
            return target.getName();
        }
        Symbol symbol = currentProgram.getSymbolTable().getPrimarySymbol(destination);
        return symbol == null ? hex(destination) : symbol.getName();
    }

    private void decompile(Function function, int timeout, JsonObject record) {
        DecompInterface decompiler = new DecompInterface();
        try {
            if (!decompiler.openProgram(currentProgram)) {
                fail(record, "decompilation_failed", "Decompiler could not open the program.", "error");
                return;
            }
            DecompileResults result = decompiler.decompileFunction(function, timeout, monitor);
            if (result != null && result.isTimedOut()) {
                fail(record, "decompilation_timeout", "Decompiler exceeded its timeout.", "timeout");
                return;
            }
            if (monitor.isCancelled() || (result != null && result.isCancelled())) {
                fail(record, "cancelled", "Decompilation was cancelled.", "cancelled");
                return;
            }
            if (result == null || !result.decompileCompleted()) {
                fail(record, "decompilation_failed", "Decompiler did not complete.", "error");
                return;
            }
            DecompiledFunction decompiled = result.getDecompiledFunction();
            if (decompiled == null || decompiled.getC() == null || decompiled.getC().isBlank()) {
                fail(record, "decompilation_failed", "Decompiler produced no C text.", "error");
                return;
            }
            record.add("decompilation", decompilation("ok",
                decompiled.getC().replace("\r\n", "\n").replace('\r', '\n')));
        }
        catch (RuntimeException exception) {
            fail(record, "decompilation_failed", "Decompiler failed.", "error");
        }
        finally {
            decompiler.dispose();
        }
    }

    private static String hex(Address address) {
        return "0x" + Long.toUnsignedString(address.getOffset(), 16);
    }

    private static JsonObject decompilation(String status, String text) {
        JsonObject result = new JsonObject();
        result.addProperty("status", status);
        result.addProperty("text", text);
        return result;
    }

    private static void fail(JsonObject record, String code, String message, String status) {
        JsonObject error = new JsonObject();
        error.addProperty("code", code);
        error.addProperty("message", message);
        record.add("decompilation", decompilation(status, ""));
        record.add("error", error);
    }

    private static void writeRecord(Path output, JsonObject record) throws IOException {
        Files.createDirectories(output.getParent());
        Path temporary = Files.createTempFile(output.getParent(), ".extract-function-", ".json.tmp");
        try {
            Files.writeString(temporary, JSON.toJson(record) + "\n", StandardCharsets.UTF_8);
            try {
                Files.move(temporary, output, StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING);
            }
            catch (AtomicMoveNotSupportedException exception) {
                Files.move(temporary, output, StandardCopyOption.REPLACE_EXISTING);
            }
        }
        finally {
            Files.deleteIfExists(temporary);
        }
    }
}

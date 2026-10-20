// @category Analysis
// @importpackage com.google.gson
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import com.google.gson.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.util.cparser.C.CParser;
import ghidra.program.model.address.*;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.Array;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.SourceType;

/** Reconstruct public bytes; export explicitly heuristic recovered stack extents. */
public class LiftBundle extends GhidraScript {
    private final Gson json = new GsonBuilder().serializeNulls().disableHtmlEscaping().create();
    private final TreeMap<Long, Byte> image = new TreeMap<>();
    private final Map<Long, Function> functions = new HashMap<>();
    private final Map<Long, Function> externals = new HashMap<>();
    private final Map<Long, Boolean> executable = new HashMap<>();
    private final Map<Long, Boolean> writable = new HashMap<>();
    private final Map<Long, JsonObject> publicFunctions = new HashMap<>();
    private Address at(long address) { return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(address); }
    private long number(JsonElement value) { return Long.parseUnsignedLong(value.getAsString().substring(2),16); }
    private String hex(long value) { return "0x" + Long.toUnsignedString(value,16); }
    private void put(long start, String raw, boolean code, boolean write) {
        byte[] bytes = java.util.HexFormat.of().parseHex(raw);
        for(int i=0;i<bytes.length;i++) {
            long address=start+i;
            Byte previous=image.putIfAbsent(address,bytes[i]);
            if(previous!=null && previous.byteValue()!=bytes[i]) throw new IllegalArgumentException("Conflicting public bytes");
            executable.merge(address,code,(a,b)->a||b);
            writable.merge(address,write,(a,b)->a||b);
        }
    }
    @Override public void run() throws Exception {
        String[] args=getScriptArgs();
        JsonObject result=new JsonObject(); result.addProperty("schema_version",2);
        result.addProperty("engine","ghidra-high-pcode");
        JsonArray output=new JsonArray(); result.add("functions",output);
        try {
            JsonObject bundle=JsonParser.parseString(Files.readString(Path.of(args[0]))).getAsJsonObject();
            JsonObject policy=JsonParser.parseString(Files.readString(Path.of(args[1]))).getAsJsonObject();
            int timeout=policy.get("decompiler_timeout_seconds").getAsInt();
            for(MemoryBlock block:currentProgram.getMemory().getBlocks()) currentProgram.getMemory().removeBlock(block,monitor);
            for(JsonElement f:bundle.getAsJsonArray("functions")) for(JsonElement i:f.getAsJsonObject().getAsJsonArray("instructions")) {
                JsonObject ins=i.getAsJsonObject();put(number(ins.get("address")),ins.get("bytes").getAsString(),true,false);
            }
            for(JsonElement d:bundle.getAsJsonArray("data")) {
                JsonObject data=d.getAsJsonObject();put(number(data.get("address")),data.get("bytes").getAsString(),false,data.get("writable").getAsBoolean());
            }
            // Fixed opaque RET adapters are library models, not recovered application code.
            for(JsonElement c:bundle.getAsJsonArray("calls")) {
                JsonObject call=c.getAsJsonObject();
                if(call.get("resolution").getAsString().equals("external")) put(number(call.get("target_address")),"c3",true,false);
            }
            while(!image.isEmpty()) {
                long start=image.firstKey(),end=start;
                boolean code=executable.get(start),write=writable.get(start);
                List<Byte> bytes=new ArrayList<>();
                while(image.containsKey(end) && executable.get(end)==code && writable.get(end)==write) bytes.add(image.remove(end++));
                byte[] raw=new byte[bytes.size()];for(int i=0;i<raw.length;i++)raw[i]=bytes.get(i);
                MemoryBlock block=createMemoryBlock("public_"+hex(start),at(start),raw,false);
                block.setRead(true);block.setWrite(write);block.setExecute(code);
            }
            for(JsonElement f:bundle.getAsJsonArray("functions")) {
                JsonObject item=f.getAsJsonObject();long entry=number(item.get("entry"));
                publicFunctions.put(entry,item);
                disassemble(at(entry));
                Function function=createFunction(at(entry),item.get("name").getAsString());
                if(function==null)function=currentProgram.getFunctionManager().getFunctionAt(at(entry));
                AddressSet body=new AddressSet();
                for(JsonElement r:item.getAsJsonArray("ranges")) {
                    JsonObject range=r.getAsJsonObject();body.add(at(number(range.get("start"))),at(number(range.get("end"))-1));
                }
                function.setBody(body); functions.put(entry,function);
            }
            JsonObject contracts=policy.getAsJsonObject("library_contracts");
            for(JsonElement c:bundle.getAsJsonArray("calls")) {
                JsonObject call=c.getAsJsonObject();long target=number(call.get("target_address"));
                if(call.get("resolution").getAsString().equals("external") && !externals.containsKey(target)) {
                    String name=call.get("target_name").getAsString();disassemble(at(target));
                    Function function=createFunction(at(target),name);
                    if(function==null)function=currentProgram.getFunctionManager().getFunctionAt(at(target));
                    externals.put(target,function);
                    if(contracts.has(name)) {
                        JsonObject contract=contracts.getAsJsonObject(name);
                        FunctionDefinition signature=(FunctionDefinition)new CParser(currentProgram.getDataTypeManager()).parse(contract.get("prototype").getAsString());
                        if(!new ApplyFunctionSignatureCmd(at(target),signature,SourceType.USER_DEFINED).applyTo(currentProgram)) throw new IllegalStateException("Library signature failed");
                        if(contract.get("kind").getAsString().equals("terminate"))function.setNoReturn(true);
                    }
                }
                if(call.get("kind").getAsString().equals("tail")) {
                    Instruction instruction=currentProgram.getListing().getInstructionAt(at(number(call.get("site"))));
                    if(instruction!=null) instruction.setFlowOverride(FlowOverride.CALL_RETURN);
                }
            }
            // Callee-first signature recovery uses public call relationships, never source declarations.
            List<Long> order=new ArrayList<>();java.util.HashSet<Long> active=new java.util.HashSet<>();
            java.util.HashSet<Long> done=new java.util.HashSet<>();
            for(Long entry:new java.util.TreeSet<>(functions.keySet())) visit(entry,bundle,active,done,order);
            for(Long entry:order) {
                DecompInterface decompiler=new DecompInterface();
                try {
                    decompiler.openProgram(currentProgram);
                    DecompileResults decompiled=decompiler.decompileFunction(functions.get(entry),timeout,monitor);
                    if(!decompiled.decompileCompleted())throw new IllegalStateException("P-code decompilation failed");
                    HighFunction high=decompiled.getHighFunction();
                    HighFunctionDBUtil.commitParamsToDatabase(high,false,HighFunctionDBUtil.ReturnCommitOption.NO_COMMIT,SourceType.ANALYSIS);
                    output.add(encodeFunction(high));
                } finally { decompiler.dispose(); }
            }
            result.addProperty("status","ok");
        } catch(Exception error) {
            result.addProperty("status","error");result.addProperty("error",error.getClass().getSimpleName()+": "+error.getMessage());
        }
        Files.writeString(Path.of(args[2]),json.toJson(result)+"\n");
    }
    private void visit(long entry,JsonObject bundle,java.util.Set<Long> active,java.util.Set<Long> done,List<Long> order) {
        if(done.contains(entry))return;
        if(!active.add(entry))throw new IllegalArgumentException("Recursive call graph unsupported");
        for(JsonElement c:bundle.getAsJsonArray("calls")) {
            JsonObject call=c.getAsJsonObject();
            if(number(call.get("caller"))==entry && call.get("resolution").getAsString().equals("application")) visit(number(call.get("target_entry")),bundle,active,done,order);
        }
        active.remove(entry);done.add(entry);order.add(entry);
    }
    private JsonObject node(Varnode value) {
        JsonObject node=new JsonObject();
        node.addProperty("id",value instanceof VarnodeAST ? Integer.toString(((VarnodeAST)value).getUniqueId()):value.toString());
        node.addProperty("space",value.getAddress().getAddressSpace().getName());
        node.addProperty("offset",hex(value.getOffset()));node.addProperty("size",value.getSize());
        if(value.isInput() && value.getHigh() instanceof HighParam)node.addProperty("parameter",((HighParam)value.getHigh()).getSlot());
        else node.add("parameter",JsonNull.INSTANCE);
        node.addProperty("stack_base",value.isInput() && value.getAddress().equals(currentProgram.getCompilerSpec().getStackPointer().getAddress()));
        return node;
    }
    private JsonObject encodeFunction(HighFunction function) throws Exception {
        JsonObject result=new JsonObject();result.addProperty("entry",hex(function.getFunction().getEntryPoint().getOffset()));
        result.addProperty("parameter_count",function.getLocalSymbolMap().getNumParams());
        JsonArray locals=new JsonArray();result.add("stack_variables",locals);
        var symbols=function.getLocalSymbolMap().getSymbols();
        while(symbols.hasNext()) {
            HighSymbol symbol=symbols.next();
            VariableStorage storage=symbol.getStorage();
            if(symbol.isParameter() || storage==null || !storage.isStackStorage())continue;
            JsonObject local=new JsonObject();
            local.addProperty("offset",storage.getStackOffset());local.addProperty("size",symbol.getSize());
            local.addProperty("array",symbol.getDataType() instanceof Array);
            local.addProperty("type",symbol.getDataType().getName());
            local.addProperty("whole_function",symbol.getPCAddress()==null);
            locals.add(local);
        }
        result.add("stack_register",node(new Varnode(currentProgram.getCompilerSpec().getStackPointer().getAddress(),8)));
        result.add("frame_register",node(new Varnode(currentProgram.getRegister("RBP").getAddress(),8)));
        JsonArray writes=new JsonArray();result.add("native_writes",writes);
        JsonObject publicFunction=publicFunctions.get(function.getFunction().getEntryPoint().getOffset());
        for(JsonElement i:publicFunction.getAsJsonArray("instructions")) {
            JsonObject ins=i.getAsJsonObject();String mnemonic=ins.get("mnemonic").getAsString().toUpperCase();
            // ABI call/return and PUSH mechanics do not establish any C buffer object bound.
            if(mnemonic.equals("PUSH") || mnemonic.equals("CALL"))continue;
            Instruction nativeInstruction=currentProgram.getListing().getInstructionAt(at(number(ins.get("address"))));
            if(nativeInstruction==null) {
                disassemble(at(number(ins.get("address"))));
                nativeInstruction=currentProgram.getListing().getInstructionAt(at(number(ins.get("address"))));
            }
            if(nativeInstruction==null || nativeInstruction.getLength()!=ins.get("size").getAsInt() ||
                    !java.util.HexFormat.of().formatHex(nativeInstruction.getBytes()).equals(ins.get("bytes").getAsString())) {
                throw new IllegalStateException("Public instruction reconstruction differs");
            }
            for(PcodeOp nativeOp:nativeInstruction.getPcode()) {
                int size=0;
                if(nativeOp.getOpcode()==PcodeOp.STORE)size=nativeOp.getInput(2).getSize();
                else if(nativeOp.getOutput()!=null && nativeOp.getOutput().getAddress().isMemoryAddress())size=nativeOp.getOutput().getSize();
                if(size>0) {
                    JsonObject write=new JsonObject();write.addProperty("address",ins.get("address").getAsString());
                    write.addProperty("size",size);writes.add(write);
                }
            }
        }
        JsonArray blocks=new JsonArray();result.add("blocks",blocks);
        for(PcodeBlockBasic block:function.getBasicBlocks()) {
            JsonObject row=new JsonObject();row.addProperty("index",block.getIndex());
            row.addProperty("start",hex(block.getStart().getOffset()));
            JsonArray in=new JsonArray(),out=new JsonArray(),ops=new JsonArray();
            for(int i=0;i<block.getInSize();i++)in.add(block.getIn(i).getIndex());
            for(int i=0;i<block.getOutSize();i++)out.add(block.getOut(i).getIndex());
            row.add("incoming",in);row.add("outgoing",out);row.add("ops",ops);
            JsonArray nativeInstructions=new JsonArray();row.add("instructions",nativeInstructions);
            for(JsonElement i:publicFunction.getAsJsonArray("instructions")) {
                JsonObject ins=i.getAsJsonObject();
                if(!block.contains(at(number(ins.get("address")))))continue;
                Instruction instruction=currentProgram.getListing().getInstructionAt(at(number(ins.get("address"))));
                JsonObject raw=new JsonObject();raw.addProperty("address",ins.get("address").getAsString());
                raw.addProperty("protocol",ins.get("mnemonic").getAsString().equalsIgnoreCase("PUSH"));
                raw.addProperty("call",instruction.getFlowType().isCall());
                JsonArray rawOps=new JsonArray();raw.add("ops",rawOps);
                for(PcodeOp op:instruction.getPcode()) {
                    JsonObject item=new JsonObject();item.addProperty("opcode",op.getMnemonic());
                    item.addProperty("address",ins.get("address").getAsString());
                    item.add("output",op.getOutput()==null ? JsonNull.INSTANCE:node(op.getOutput()));
                    JsonArray inputs=new JsonArray();for(int j=0;j<op.getNumInputs();j++)inputs.add(node(op.getInput(j)));
                    item.add("inputs",inputs);rawOps.add(item);
                }
                nativeInstructions.add(raw);
            }
            var iterator=block.getIterator();
            while(iterator.hasNext()) {
                PcodeOp op=iterator.next();JsonObject item=new JsonObject();
                item.addProperty("opcode",op.getMnemonic());item.addProperty("address",hex(op.getSeqnum().getTarget().getOffset()));
                item.add("output",op.getOutput()==null ? JsonNull.INSTANCE:node(op.getOutput()));
                JsonArray inputs=new JsonArray();for(int i=0;i<op.getNumInputs();i++)inputs.add(node(op.getInput(i)));
                item.add("inputs",inputs);ops.add(item);
            }
            blocks.add(row);
        }
        return result;
    }
}

# Ghidra Feature Extractor for Vestigo
# To be run with Ghidra Headless Analyzer

import json
import math
from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.block import BasicBlockModel
from ghidra.util.task import TaskMonitor

# --- Constants Database ---
CRYPTO_CONSTANTS = {
    "AES_SBOX_START": [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5],
    "SHA256_K": [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5],
    "MD5_K": [0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee],
    "DELTA_TEA": 0x9e3779b9
}

def get_function_label(name):
    name_lower = name.lower()
    if "aes" in name_lower or "rijndael" in name_lower:
        return "AES"
    elif "sha256" in name_lower or "sha-256" in name_lower:
        return "SHA256"
    elif "rsa" in name_lower:
        return "RSA"
    elif "chacha" in name_lower:
        return "ChaCha20"
    elif "ecc" in name_lower or "elliptic" in name_lower:
        return "ECC"
    else:
        return "Non-Crypto"

def get_scc_count(graph_nodes, graph_edges):
    visited = set()
    stack = []
    on_stack = set()
    ids = {}
    low = {}
    counters = {'scc': 0, 'id': 0}  # Use dict instead of nonlocal

    def dfs(at):
        stack.append(at)
        on_stack.add(at)
        ids[at] = low[at] = counters['id']
        counters['id'] += 1

        for to in graph_edges.get(at, []):
            if to not in ids:
                dfs(to)
                low[at] = min(low[at], low[to])
            elif to in on_stack:
                low[at] = min(low[at], ids[to])

        if ids[at] == low[at]:
            while stack:
                node = stack.pop()
                on_stack.remove(node)
                if node == at: break
            counters['scc'] += 1

    for node in graph_nodes:
        if node not in ids:
            dfs(node)
    return counters['scc']

def analyze_graph_structure(graph_nodes, graph_edges):
    visited = set()
    recursion_stack = set()
    counters = {'loops': 0}  # Use dict instead of nonlocal
    loop_depths = {node: 0 for node in graph_nodes}
    back_edges = set()
    
    def dfs(u, depth):
        visited.add(u)
        recursion_stack.add(u)
        
        for v in graph_edges.get(u, []):
            if v not in visited:
                dfs(v, depth)
            elif v in recursion_stack:
                counters['loops'] += 1
                back_edges.add((u, v))
                loop_depths[v] += 1
                loop_depths[u] += 1 
        
        recursion_stack.remove(u)

    if graph_nodes:
        start_nodes = sorted(list(graph_nodes))
        for node in start_nodes:
            if node not in visited:
                dfs(node, 0)
        
    max_depth = max(loop_depths.values()) if loop_depths else 0
    return counters['loops'], max_depth, back_edges

def get_node_features(block, monitor):
    features = {
        "instruction_count": 0,
        "opcode_histogram": {},
        "opcode_ratios": {
            "xor": 0.0, "add": 0.0, "rotate": 0.0, "multiply": 0.0, 
            "logical": 0.0, "load_store": 0.0
        },
        "bitwise_op_density": 0.0,
        "immediate_entropy": 0.0,
        "table_lookup_presence": False,
        "crypto_constant_hits": 0,
        "branch_condition_complexity": 0
    }
    
    inst_iter = currentProgram.getListing().getInstructions(block, True)
    
    total_ops = 0
    bitwise_ops = 0
    immediates = []
    condition_complexity = 0
    
    op_counts = {k: 0 for k in features["opcode_ratios"].keys()}
    
    while inst_iter.hasNext():
        inst = inst_iter.next()
        features["instruction_count"] += 1
        
        for i in range(inst.getNumOperands()):
            if inst.getOperandType(i) & 2:
                try:
                    val = inst.getScalar(i).getValue()
                    immediates.append(val)
                    for name, sig in CRYPTO_CONSTANTS.items():
                        if isinstance(sig, list):
                            if val in sig: features["crypto_constant_hits"] += 1
                        elif val == sig:
                            features["crypto_constant_hits"] += 1
                except: pass

        pcode = inst.getPcode()
        if pcode:
            for op in pcode:
                total_ops += 1
                mnemonic = op.getMnemonic()
                opcode = op.getOpcode()
                features["opcode_histogram"][mnemonic] = features["opcode_histogram"].get(mnemonic, 0) + 1
                
                if opcode in [PcodeOp.INT_XOR]:
                    op_counts["xor"] += 1
                    bitwise_ops += 1
                    condition_complexity += 1
                elif opcode in [PcodeOp.INT_ADD, PcodeOp.INT_SUB]:
                    op_counts["add"] += 1
                    condition_complexity += 1
                elif opcode in [PcodeOp.INT_LEFT, PcodeOp.INT_RIGHT, PcodeOp.INT_SRIGHT]:
                    op_counts["rotate"] += 1
                    bitwise_ops += 1
                elif opcode in [PcodeOp.INT_MULT]:
                    op_counts["multiply"] += 1
                elif opcode in [PcodeOp.INT_AND, PcodeOp.INT_OR, PcodeOp.INT_2COMP]:
                    op_counts["logical"] += 1
                    bitwise_ops += 1
                    condition_complexity += 1
                elif opcode in [PcodeOp.LOAD, PcodeOp.STORE]:
                    op_counts["load_store"] += 1
                    if opcode == PcodeOp.LOAD:
                        inputs = op.getInputs()
                        if len(inputs) > 1 and not inputs[1].isConstant():
                            features["table_lookup_presence"] = True
                elif opcode in [PcodeOp.INT_EQUAL, PcodeOp.INT_NOTEQUAL, PcodeOp.INT_LESS, PcodeOp.INT_SLESS, PcodeOp.INT_LESSEQUAL, PcodeOp.INT_SLESSEQUAL]:
                     condition_complexity += 2

    if total_ops > 0:
        features["bitwise_op_density"] = float(bitwise_ops) / total_ops
        for k in op_counts:
            features["opcode_ratios"]["{}_ratio".format(k)] = float(op_counts[k]) / total_ops

    features["branch_condition_complexity"] = condition_complexity

    if immediates:
        freq = {}
        for val in immediates:
            freq[val] = freq.get(val, 0) + 1
        entropy = 0
        for count in freq.values():
            p = float(count) / len(immediates)
            entropy -= p * math.log(p, 2)
        features["immediate_entropy"] = entropy
        
    return features

def analyze_function(func):
    monitor = TaskMonitor.DUMMY
    block_model = BasicBlockModel(currentProgram)
    blocks = block_model.getCodeBlocksContaining(func.getBody(), monitor)
    
    graph_nodes = set()
    graph_edges = {} 
    
    node_features_map = {}
    total_inst_count = 0
    num_blocks = 0
    
    while blocks.hasNext():
        block = blocks.next()
        block_addr = block.getFirstStartAddress().toString()
        graph_nodes.add(block_addr)
        num_blocks += 1
        
        nf = get_node_features(block, monitor)
        nf["address"] = block_addr
        node_features_map[block_addr] = nf
        total_inst_count += nf["instruction_count"]
        
        dests = block.getDestinations(monitor)
        if block_addr not in graph_edges: graph_edges[block_addr] = []
        
        while dests.hasNext():
            ref = dests.next()
            dest_addr = ref.getDestinationAddress().toString()
            graph_edges[block_addr].append(dest_addr)

    loop_count, loop_depth, back_edges = analyze_graph_structure(graph_nodes, graph_edges)
    scc_count = get_scc_count(graph_nodes, graph_edges)
    num_edges = sum(len(v) for v in graph_edges.values())
    cyclomatic_complexity = num_edges - num_blocks + 2
    exits = sum(1 for n in graph_nodes if not graph_edges.get(n))
    
    branch_density = 0
    if total_inst_count > 0:
        branches = sum(1 for n in graph_edges if len(graph_edges[n]) > 1)
        branch_density = float(branches) / total_inst_count

    graph_features = {
        "num_basic_blocks": num_blocks,
        "num_edges": num_edges,
        "cyclomatic_complexity": cyclomatic_complexity,
        "loop_count": loop_count,
        "loop_depth": loop_depth,
        "branch_density": branch_density,
        "average_block_size": float(total_inst_count) / num_blocks if num_blocks else 0,
        "num_entry_exit_paths": 1 + exits,
        "strongly_connected_components": scc_count
    }
    
    edge_features_list = []
    for src in graph_edges:
        for dst in graph_edges[src]:
            edge_type = "unconditional"
            if len(graph_edges[src]) > 1:
                edge_type = "conditional"
            
            edge_features_list.append({
                "src": src,
                "dst": dst,
                "edge_type": edge_type,
                "is_loop_edge": (src, dst) in back_edges
            })

    func_name = func.getName()
    return {
        "name": func_name,
        "label": get_function_label(func_name), # Added Label
        "address": func.getEntryPoint().toString(),
        "graph_level": graph_features,
        "node_level": list(node_features_map.values()),
        "edge_level": edge_features_list
    }

def main():
    program_name = currentProgram.getName()
    output_file = "{}.json".format(program_name)
    
    results = {"binary": program_name, "functions": []}
    
    func_iter = currentProgram.getFunctionManager().getFunctions(True)
    for func in func_iter:
        if not func.isThunk():
            results["functions"].append(analyze_function(func))
            
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)
        
    print("Analysis complete. Saved to {}".format(output_file))

if __name__ == "__main__":
    main()

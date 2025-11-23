# Ghidra Feature Extractor for Vestigo
# To be run with Ghidra Headless Analyzer

import json
import math
from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.block import BasicBlockModel
from ghidra.util.task import TaskMonitor

# --- Constants Database ---
# Complete AES S-Box (256 bytes)
AES_SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

# AES Rcon (Round Constants)
AES_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

# SHA-256 Initial Hash Values
SHA256_INIT = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 
               0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

# SHA-256 Round Constants (first 8)
SHA256_K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
            0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5]

# SHA-1 Initial Hash Values
SHA1_INIT = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]

# MD5 Constants
MD5_K = [0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee]

# TEA Delta
DELTA_TEA = 0x9e3779b9

CRYPTO_CONSTANTS = {
    "AES_SBOX": AES_SBOX,
    "AES_RCON": AES_RCON,
    "SHA256_INIT": SHA256_INIT,
    "SHA256_K": SHA256_K,
    "SHA1_INIT": SHA1_INIT,
    "MD5_K": MD5_K,
    "DELTA_TEA": DELTA_TEA
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

def detect_crypto_signatures(func, immediates):
    """Detect specific cryptographic algorithm signatures"""
    signatures = {
        "has_aes_sbox": 0,
        "has_aes_rcon": 0,
        "has_sha_constants": 0,
        "rsa_bigint_detected": 0
    }
    
    # Check for AES S-Box (look for consecutive S-Box values)
    aes_sbox_matches = 0
    for i in range(len(immediates) - 7):
        consecutive = immediates[i:i+8]
        # Check if these 8 consecutive values match any position in S-Box
        for j in range(len(AES_SBOX) - 7):
            if consecutive == AES_SBOX[j:j+8]:
                aes_sbox_matches += 1
                break
    if aes_sbox_matches >= 2:
        signatures["has_aes_sbox"] = 1
    
    # Check for AES Rcon
    rcon_matches = sum(1 for val in immediates if val in AES_RCON)
    if rcon_matches >= 3:
        signatures["has_aes_rcon"] = 1
    
    # Check for SHA constants (SHA-256, SHA-1)
    sha_matches = 0
    for val in immediates:
        if val in SHA256_INIT or val in SHA256_K or val in SHA1_INIT:
            sha_matches += 1
    if sha_matches >= 2:
        signatures["has_sha_constants"] = 1
    
    # Check for RSA BigInt patterns (large constants, modular arithmetic indicators)
    large_constants = sum(1 for val in immediates if val > 0xFFFF)
    if large_constants >= 5:
        signatures["rsa_bigint_detected"] = 1
    
    return signatures

def calculate_entropy(values):
    """Calculate Shannon entropy of a list of values"""
    if not values:
        return 0.0
    freq = {}
    for val in values:
        freq[val] = freq.get(val, 0) + 1
    entropy = 0.0
    total = float(len(values))
    for count in freq.values():
        p = count / total
        entropy -= p * math.log(p, 2)
    return entropy

def calculate_function_entropy_metrics(func, opcode_list, cyclomatic_complexity, total_instructions):
    """Calculate entropy metrics for the function"""
    metrics = {
        "function_byte_entropy": 0.0,
        "opcode_entropy": 0.0,
        "cyclomatic_complexity_density": 0.0
    }
    
    # Calculate function byte entropy
    try:
        func_body = func.getBody()
        byte_values = []
        for addr_range in func_body:
            addr = addr_range.getMinAddress()
            end_addr = addr_range.getMaxAddress()
            while addr.compareTo(end_addr) <= 0:
                try:
                    byte_val = currentProgram.getMemory().getByte(addr) & 0xFF
                    byte_values.append(byte_val)
                    addr = addr.add(1)
                except:
                    break
        if byte_values:
            metrics["function_byte_entropy"] = calculate_entropy(byte_values)
    except:
        pass
    
    # Calculate opcode entropy
    if opcode_list:
        metrics["opcode_entropy"] = calculate_entropy(opcode_list)
    
    # Calculate cyclomatic complexity density
    if total_instructions > 0:
        metrics["cyclomatic_complexity_density"] = float(cyclomatic_complexity) / total_instructions
    
    return metrics

def extract_instruction_ngrams(instruction_mnemonics):
    """Extract instruction bigrams and calculate unique n-gram count"""
    if len(instruction_mnemonics) < 2:
        return {"top_5_bigrams": [], "unique_ngram_count": 0}
    
    # Generate bigrams
    bigrams = []
    for i in range(len(instruction_mnemonics) - 1):
        bigram = "{} {}".format(instruction_mnemonics[i], instruction_mnemonics[i+1])
        bigrams.append(bigram)
    
    # Count bigram frequencies
    bigram_freq = {}
    for bg in bigrams:
        bigram_freq[bg] = bigram_freq.get(bg, 0) + 1
    
    # Get top 5 bigrams
    sorted_bigrams = sorted(bigram_freq.items(), key=lambda x: x[1], reverse=True)
    top_5 = [bg for bg, count in sorted_bigrams[:5]]
    
    return {
        "top_5_bigrams": top_5,
        "unique_ngram_count": len(bigram_freq)
    }

def analyze_data_references(func):
    """Analyze data references including strings, rodata, and stack frame size"""
    refs = {
        "string_refs_count": 0,
        "rodata_refs_count": 0,
        "stack_frame_size": 0
    }
    
    # Count string references
    string_refs = func.getProgram().getReferenceManager().getReferencesFrom(func.getEntryPoint())
    for ref in string_refs:
        to_addr = ref.getToAddress()
        data = currentProgram.getListing().getDataAt(to_addr)
        if data and data.hasStringValue():
            refs["string_refs_count"] += 1
    
    # Count rodata references (read-only memory sections)
    memory = currentProgram.getMemory()
    for ref in func.getProgram().getReferenceManager().getReferencesFrom(func.getEntryPoint()):
        to_addr = ref.getToAddress()
        block = memory.getBlock(to_addr)
        if block and not block.isWrite() and block.isInitialized():
            refs["rodata_refs_count"] += 1
    
    # Estimate stack frame size from local variables
    try:
        stack_frame = func.getStackFrame()
        if stack_frame:
            refs["stack_frame_size"] = stack_frame.getFrameSize()
    except:
        pass
    
    return refs

def categorize_operations(pcode_ops):
    """Categorize operations into arithmetic, bitwise, crypto-like, and memory ops"""
    counts = {
        "arithmetic_ops": 0,
        "bitwise_ops": 0,
        "crypto_like_ops": 0,
        "mem_ops_ratio": 0.0
    }
    
    total_ops = len(pcode_ops)
    mem_ops = 0
    
    for op in pcode_ops:
        opcode = op.getOpcode()
        
        # Arithmetic operations
        if opcode in [PcodeOp.INT_ADD, PcodeOp.INT_SUB, PcodeOp.INT_MULT, 
                      PcodeOp.INT_DIV, PcodeOp.INT_SDIV, PcodeOp.INT_REM, PcodeOp.INT_SREM]:
            counts["arithmetic_ops"] += 1
        
        # Bitwise operations
        if opcode in [PcodeOp.INT_AND, PcodeOp.INT_OR, PcodeOp.INT_XOR, 
                      PcodeOp.INT_2COMP, PcodeOp.INT_NEGATE]:
            counts["bitwise_ops"] += 1
        
        # Crypto-like operations (XOR, rotations, shifts)
        if opcode in [PcodeOp.INT_XOR, PcodeOp.INT_LEFT, PcodeOp.INT_RIGHT, 
                      PcodeOp.INT_SRIGHT]:
            counts["crypto_like_ops"] += 1
        
        # Memory operations
        if opcode in [PcodeOp.LOAD, PcodeOp.STORE]:
            mem_ops += 1
    
    if total_ops > 0:
        counts["mem_ops_ratio"] = float(mem_ops) / total_ops
    
    return counts

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
    
    # Function-wide data collection for new features
    all_immediates = []
    all_instruction_mnemonics = []
    all_pcode_ops = []
    all_opcode_mnemonics = []
    
    while blocks.hasNext():
        block = blocks.next()
        block_addr = block.getFirstStartAddress().toString()
        graph_nodes.add(block_addr)
        num_blocks += 1
        
        nf = get_node_features(block, monitor)
        nf["address"] = block_addr
        node_features_map[block_addr] = nf
        total_inst_count += nf["instruction_count"]
        
        # Collect function-wide data
        inst_iter = currentProgram.getListing().getInstructions(block, True)
        while inst_iter.hasNext():
            inst = inst_iter.next()
            mnemonic = inst.getMnemonicString()
            all_instruction_mnemonics.append(mnemonic)
            
            # Collect immediates
            for i in range(inst.getNumOperands()):
                if inst.getOperandType(i) & 2:
                    try:
                        val = inst.getScalar(i).getValue()
                        all_immediates.append(val)
                    except:
                        pass
            
            # Collect pcode operations
            pcode = inst.getPcode()
            if pcode:
                for op in pcode:
                    all_pcode_ops.append(op)
                    all_opcode_mnemonics.append(op.getMnemonic())
        
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

    # Extract new features
    crypto_sigs = detect_crypto_signatures(func, all_immediates)
    entropy_metrics = calculate_function_entropy_metrics(func, all_opcode_mnemonics, cyclomatic_complexity, total_inst_count)
    instruction_seq = extract_instruction_ngrams(all_instruction_mnemonics)
    data_refs = analyze_data_references(func)
    op_counts = categorize_operations(all_pcode_ops)

    func_name = func.getName()
    return {
        "name": func_name,
        "label": get_function_label(func_name),
        "address": func.getEntryPoint().toString(),
        "crypto_signatures": crypto_sigs,
        "entropy_metrics": entropy_metrics,
        "instruction_sequence": instruction_seq,
        "data_references": data_refs,
        "op_category_counts": op_counts,
        "graph_level": graph_features,
        "node_level": list(node_features_map.values()),
        "edge_level": edge_features_list
    }

def main():
    import os
    program_name = currentProgram.getName()
    
    # Output to ghidra_output directory
    output_dir = "ghidra_output"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    output_file = os.path.join(output_dir, "{}.json".format(program_name))
    
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

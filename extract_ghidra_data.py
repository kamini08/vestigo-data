# @category FeatureExtraction

import json

prog = getCurrentProgram()
fm = prog.getFunctionManager()
listing = prog.getListing()

from ghidra.program.model.block import BasicBlockModel

block_model = BasicBlockModel(prog)

output = {"functions": []}

for fn in fm.getFunctions(True):
    fn_json = {
        "name": fn.getName(),
        "entry": hex(fn.getEntryPoint().getOffset()),
        "basicBlocks": []
    }

    # Get basic blocks inside this function body
    blocks = block_model.getCodeBlocksContaining(fn.getBody(), monitor)

    for bb in blocks:
        bb_json = {
            "start": hex(bb.getFirstStartAddress().getOffset()),
            "instructions": []
        }

        instr_iter = listing.getInstructions(bb, True)
        for ins in instr_iter:
            bb_json["instructions"].append({
                "op": ins.getMnemonicString(),
                "full": str(ins)
            })

        fn_json["basicBlocks"].append(bb_json)

    output["functions"].append(fn_json)

with open("ghidra_output.json", "w") as f:
    f.write(json.dumps(output, indent=2))

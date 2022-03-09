using System;
using System.Collections.Generic;

namespace Cryptanalysis.Core {
    abstract class Gate {
        public readonly string Name;
        public Gate(string name) {
            inputs = new List<InSlot>();
            outputs = new List<OutSlot>();
            Name = name;
        }
        public Gate(string name, Gate g) : this(name) {
            foreach (var input in g.inputs) {
                inputs.Add(new InSlot(input));
            }
            foreach (var output in g.outputs) {
                outputs.Add(new OutSlot(output));
            }
        }
        protected List<InSlot> inputs;
        protected List<OutSlot> outputs;
        public InSlot GetInput(int i) {
            return inputs[i];
        }
        public OutSlot GetOutput(int i) {
            return outputs[i];
        }
        public int OutputsCount => outputs.Count;
        public int InputsCount => inputs.Count;
        public abstract void Run();
        public abstract Gate Duplicate();
    }
}

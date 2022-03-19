namespace Cryptanalysis.Core.Common {
    class DummyGate : Gate {
        private int length;
        public DummyGate(string name, int length) : base(name) {
            this.length = length;
            for (int i = 0; i < length; i++) {
                inputs.Add(new InSlot());
                outputs.Add(new OutSlot());
            }
        }
        private DummyGate(DummyGate dg) : this(dg.Name, dg.InputsCount) {

        }
        public override Gate Duplicate() => new DummyGate(this);

        public override void Run() {
            for (int i = 0; i < InputsCount; i++) {
                outputs[i].Set(inputs[i].Get);
            }
        }
    }
}

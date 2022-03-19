using System;

namespace Cryptanalysis.Core.Common {
    abstract class ASbox : Gate {
        private int length;
        protected (int source, int target)[] table;
        private TransitionFunction func;
        public ASbox(string name, (int source, int target)[] table) : base(name) {
            SetLength(table);
            this.table = table;
            inputs = InSlot.GetInSlots(length);
            outputs = OutSlot.GetOutSlots(length);
            func = CreateTransitionFunction();
        }
        private bool SetLength(Array table) {
            int l = table.Length;
            double logL = Math.Log2(l);
            var logLfloor = Math.Floor(logL);
            if (logLfloor == logL) {
                length = (int)logL;
                return true;
            }
            length = -1; //Fail value
            return false;
        }
        protected TransitionFunction CreateTransitionFunction() {
            var r = new TransitionFunction(length);
            for (int i = 0; i < table.Length; i++) {
                r.AddInputOutputPair(
                    Utils.ConvertToBinary(table[i].source, length),
                    Utils.ConvertToBinary(table[i].target, length));
            }
            return r;
        }
        public override void Run() {
            func.Perform(ref inputs, ref outputs);
        }
    }
}

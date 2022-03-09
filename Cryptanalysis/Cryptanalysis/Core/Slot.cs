using System.Collections.Generic;
using static Cryptanalysis.Core.Constants;

namespace Cryptanalysis.Core {
    internal class Slot {
        private byte val;
        public Slot(byte initValue = BYTE_UNDEFINED) {
            val = initValue;
        }
        public byte Get => val;
        public void Set(byte value) => val = value;
        public Slot Duplicate() {
            return new Slot(this.Get);
        }

    }
    class InSlot : Slot {
        public InSlot(byte initValue = BYTE_UNDEFINED) : base(initValue) { }
        public InSlot(Slot sl) : base(sl.Get) { }
        public static List<InSlot> GetInSlots(int len, byte initValue = BYTE_UNDEFINED) {
            var r = new List<InSlot>();
            for (int i = 0; i < len; i++) {
                r.Add(new InSlot(initValue));
            }
            return r;
        }
    }
    class OutSlot : Slot {
        public OutSlot(byte initValue = BYTE_UNDEFINED) : base(initValue) { }
        public OutSlot(Slot sl) : base(sl.Get) { }

        public static List<OutSlot> GetOutSlots(int len, byte initValue = BYTE_UNDEFINED) {
            var r = new List<OutSlot>();
            for (int i = 0; i < len; i++) {
                r.Add(new OutSlot(initValue));
            }
            return r;
        }
    }
}

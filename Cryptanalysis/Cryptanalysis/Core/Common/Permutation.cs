using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cryptanalysis.Core.Common {
    class Permutation : Model {
        private (int source, int target)[] table;
        public Permutation(string name, (int source, int target)[] table) : base(name) {
            inputs = InSlot.GetInSlots(table.Length);
            outputs = OutSlot.GetOutSlots(table.Length);
            this.table = table;
            SetConnections();
        }
        public Permutation(Permutation perm) : this(perm.Name, perm.table) {

        }
        public static (int source, int target)[] ParseParmutationTable(string s, char separator = ',') {
            //TODO - missing validity check
            var nums = s.Split(separator);
            var table = new (int source, int target)[nums.Length];
            for (int i = 0; i < nums.Length; i++) {
                table[i] = ((i, int.Parse(nums[i])));
            }
            return table;
        }
        private void SetConnections() {
            for (int i = 0; i < table.Length; i++) {
                connections.Add(
                    new InternalConnection(inputs[table[i].source], outputs[table[i].target]));
            }
        }
        public override Gate Duplicate() {
            return new Permutation(this);
        }
    }
}

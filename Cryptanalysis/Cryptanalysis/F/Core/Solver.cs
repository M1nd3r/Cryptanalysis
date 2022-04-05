using System;
using System.Collections.Generic;
using static Cryptanalysis.Core.Utils;

namespace Cryptanalysis.F.Core {

    internal class Solution : ICloneable {
        private readonly byte[] mask;
        private readonly byte result;

        public Solution(byte[] mask, byte result) {
            this.mask = mask;
            this.result = result;
        }

        public int Length => mask.Length;
        public byte[] Mask => mask;
        public byte Result => result;

        public static Solution operator +(Solution a, Solution b) {
            if (a == null)
                throw new ArgumentNullException(nameof(a));
            if (b == null)
                throw new ArgumentNullException(nameof(b));
            if (a.mask.Length != b.mask.Length)
                throw new ArgumentException("Solutions do not have the same dimensions.");
            var mask = XORs(a.mask, b.mask);
            var result = Xor(a.result, b.result);
            return new Solution(mask, result);
        }

        public object Clone() {
            return new Solution(mask, result);
        }
    }

    internal class Solver {

        public static bool TrySolve(IList<Solution> solutions, out byte[] key) {
            if (solutions.IsNull())
                throw new ArgumentNullException(nameof(solutions));
            if (solutions.IsEmpty())
                throw new ArgumentException("List of solutions is empty", nameof(solutions));
            IList<Solution> sol = solutions.Clone();
            int len = sol[0].Length;
            key = new byte[len];
            if (sol.Count < len)
                return false;
            for (int i = 0; i < len; i++) {
                if (!TryGetPivot(sol, i, out int pivot))
                    return false;
                UpdateList(ref sol, i, pivot);
                Swap(sol, pivot, i);
            }
            for (int i = 0; i < len; i++)
                key[i] = sol[i].Result;
            return true;
        }

        private static void Swap(IList<Solution> sol, int i, int j) {
            if (i == j)
                return;
            sol.Insert(i, sol[j]);
            var t = sol[i + 1];
            sol.RemoveAt(i + 1);
            sol[j] = t;
        }

        private static bool TryGetPivot(IList<Solution> sol, int i, out int pivot) {
            pivot = -1;
            for (int j = i; j < sol.Count; j++) {
                if (sol[j].Mask[i] == 1) {
                    pivot = j;
                    return true;
                }
            }
            return false;
        }

        private static void UpdateList(ref IList<Solution> sol, int column, int pivot) {
            for (int j = 0; j < sol.Count; j++) {
                if (j == pivot)
                    continue;
                if (sol[j].Mask[column] == 1)
                    sol[j] += sol[pivot];
            }
        }
    }
}

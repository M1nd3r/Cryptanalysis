using System;
using System.Collections.Generic;

namespace Cryptanalysis.F.Core {

    internal class Solver {

        public static bool TrySolve(IList<Solution> solutions, out byte[] key) {
            if (solutions == null)
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
            for (int i = 0; i < sol.Count; i++) {
                if (i == pivot)
                    continue;
                if (sol[i].Mask[column] == 1)
                    sol[i] += sol[pivot];
            }
        }
    }
}

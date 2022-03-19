using System;

namespace Cryptanalysis.Core {
    class DifferenceDistributionTable {
        public readonly int[,] Arr;
        private DifferenceDistributionTable(int[,] arr) {
            this.Arr = arr;
        }
        public static DifferenceDistributionTable getDDT(Gate g) {
            if (g.InputsCount <= 0 || g.OutputsCount <= 0)
                throw new ArgumentException();
            int
                inputMax = (int)Math.Pow(2, g.InputsCount),
                outputMax = (int)Math.Pow(2, g.OutputsCount);
            int[,] arr = new int[inputMax, outputMax];
            for (int i = 0; i < inputMax; i++) {

            }
            throw new NotImplementedException();

            //return new DifferenceDistributionTable(arr);
        }
        public static DifferenceDistributionTable getCipherFourDDT(Gate g) {

            int[,] arr = {
                {16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
                { 0, 0, 6, 0, 0, 0, 0, 2, 0, 2, 0, 0, 2, 0, 4, 0},
                { 0, 6, 6, 0, 0, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 0},
                { 0, 0, 0, 6, 0, 2, 0, 0, 2, 0, 0, 0, 4, 0, 2, 0},
                { 0, 0, 0, 2, 0, 2, 4, 0, 0, 2, 2, 2, 0, 0, 2, 0},
                { 0, 2, 2, 0, 4, 0, 0, 4, 2, 0, 0, 2, 0, 0, 0, 0},
                { 0, 0, 2, 0, 4, 0, 0, 2, 2, 0, 2, 2, 2, 0, 0, 0},
                { 0, 0, 0, 0, 0, 4, 4, 0, 2, 2, 2, 2, 0, 0, 0, 0},
                { 0, 0, 0, 0, 0, 2, 0, 2, 4, 0, 0, 4, 0, 2, 0, 2},
                { 0, 2, 0, 0, 0, 2, 2, 2, 0, 4, 2, 0, 0, 0, 0, 2},
                { 0, 0, 0, 0, 2, 2, 0, 0, 0, 4, 4, 0, 2, 2, 0, 0},
                { 0, 0, 0, 2, 2, 0, 2, 2, 2, 0, 0, 4, 0, 0, 2, 0},
                { 0, 4, 0, 2, 0, 2, 0, 0, 2, 0, 0, 0, 0, 0, 6, 0},
                { 0, 0, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 6, 2, 0, 4},
                { 0, 2, 0, 4, 2, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 6}
            };
            return new DifferenceDistributionTable(arr);
        }
    }
}

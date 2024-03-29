﻿using System;
using Cryptanalysis.Core;
using static Cryptanalysis.Core.Verifiers;

namespace Cryptanalysis.Common {

    internal class Permutation : AChanger {
        private readonly int[] table, invTable;

        public Permutation(int[] table) {
            if (!VerifyContentIsWithinRange(table))
                throw new ArgumentException("Table contains values out of range!");
            this.table = table;
            this.invTable = new int[table.Length];
            GenerateInverseTable();
        }

        protected override void ApplyInternal(ref byte[] arr) {
            CheckAreEqual(arr.Length, table.Length);
            ApplyTable(table, ref arr);
        }

        protected override void ApplyInverseInternal(ref byte[] arr) {
            CheckAreEqual(arr.Length, invTable.Length);
            ApplyTable(invTable, ref arr);
        }

        private static void ApplyTable(int[] tableToApply, ref byte[] arr) {
            var r = new byte[arr.Length];
            for (int i = 0; i < arr.Length; i++)
                r[tableToApply[i]] = arr[i];
            arr = r;
        }

        private static bool VerifyContentIsWithinRange(int[] table) {
            for (int i = 0; i < table.Length; i++) {
                if (table[i] < 0 || table[i] >= table.Length)
                    return false;
            }
            return true;
        }

        private void GenerateInverseTable() {
            InitializeInverseTable();
            for (int i = 0; i < table.Length; i++) {
                if (invTable[table[i]] == -1)
                    invTable[table[i]] = i;
                else
                    throw new ArgumentException("Input table is not bijective");
            }
        }

        private void InitializeInverseTable() {
            for (int i = 0; i < invTable.Length; i++)
                invTable[i] = -1;
        }
    }
}

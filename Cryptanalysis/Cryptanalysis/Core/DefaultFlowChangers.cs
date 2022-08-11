using Cryptanalysis.Common;
using static Cryptanalysis.Core.Utils;

namespace Cryptanalysis.Core {

    internal class DefaultFlowChangers {

        internal static LFSR GetFinalLFSR_11_T(byte[] key) => new LFSR(GetPolynomialForLFSR(new int[] { 0, 1, 2, 4, 11 }), key);

        internal static LFSR GetFinalLFSR_11_Y(byte[] key) => new LFSR(GetPolynomialForLFSR(new int[] { 0, 2, 11 }), key);

        internal static LFSR GetFinalLFSR_15_Z(byte[] key) => new LFSR(GetPolynomialForLFSR(new int[] { 0, 1, 15 }), key);

        internal static LFSR GetFinalLFSR_7_X(byte[] key) => new LFSR(GetPolynomialForLFSR(new int[] { 0, 1, 7 }), key);

        internal static LFSR GetLFSR_11(byte[] key) => new LFSR(GetPolynomialForLFSR(new int[] { 0, 2, 11 }), key);

        internal static LFSR GetLFSR_15(byte[] key) => new LFSR(GetPolynomialForLFSR(new int[] { 0, 1, 15 }), key);

        internal static LFSR GetLFSR_7(byte[] key) => new LFSR(GetPolynomialForLFSR(new int[] { 0, 1, 7 }), key);

        internal static Sbox4 GetSbox4_1() => new Sbox4(CreateTransitionTableSbox4("64C5072E1F3D8A9B"));

        internal static Sbox4 GetSbox4_A() => new Sbox4(CreateTransitionTableSbox4("FEBC6D78039A4215"));
    }
}

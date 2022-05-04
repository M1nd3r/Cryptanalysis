using Cryptanalysis.Common;

namespace Cryptanalysis.Core {

    internal class DefaultFlowChangers {

        internal static Sbox4 GetSbox4_1() => new Sbox4(Utils.CreateTransitionTableSbox4("64C5072E1F3D8A9B"));

        internal static Sbox4 GetSbox4_A() => new Sbox4(Utils.CreateTransitionTableSbox4("FEBC6D78039A4215"));
    }
}

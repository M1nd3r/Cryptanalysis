namespace Cryptanalysis.F.Core {
    static class Verifiers {
        public static void CheckAreEqual(int a, int b) {
            if (a != b)
                throw new CheckException("Values are not equal");
        }
        public static void CheckIsZeroOrOne(byte a) {
            if (a == 0)
                return;
            if (a == 1)
                return;
            throw new CheckException("Given byte in not zero or one. Its value is " + a.ToString());
        }
    }
}

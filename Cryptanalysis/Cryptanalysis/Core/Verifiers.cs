namespace Cryptanalysis.Core {

    internal static class Verifiers {

        internal static bool AreEqual(byte[] a, byte[] b) {
            if (a == null || b == null)
                return false;
            if (a.Length != b.Length)
                return false;
            for (int i = 0; i < a.Length; i++) {
                if (a[i] != b[i])
                    return false;
            }
            return true;
        }

        internal static void CheckAreEqual(int a, int b) {
            if (a != b)
                throw new CheckException("Values are not equal");
        }

        internal static void CheckIsZeroOrOne(byte a) {
            if (a == 0)
                return;
            if (a == 1)
                return;
            throw new CheckException("Given byte in not zero or one. Its value is " + a.ToString());
        }
    }
}

using System;
using System.Collections.Generic;

namespace Cryptanalysis.F.Core {

    public static class Extensions {

        public static IList<T> Clone<T>(this IList<T> list) where T : ICloneable {
            IList<T> r = new List<T>();
            for (int i = 0; i < list.Count; i++)
                r.Add((T)list[i].Clone());
            return r;
        }

        public static bool IsEmpty<T>(this IList<T> list) {
            if (list == null)
                throw new ArgumentNullException(nameof(list));
            return list.Count <= 0;
        }

        public static T[] SubArray<T>(this T[] array, int offset, int length) {
            T[] result = new T[length];
            Array.Copy(array, offset, result, 0, length);
            return result;
        }
    }
}

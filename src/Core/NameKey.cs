using System;

namespace CryptoProExport
{
    /// <summary>
    /// Файл name.key — «дружественное» имя контейнера в формате ASN.1:
    /// <c>30 &lt;len+2&gt; 16 &lt;len&gt; &lt;имя в cp1251&gt;</c> (SEQUENCE { IA5String }).
    /// Именно это имя показывает КриптоПро CSP при перечислении контейнеров,
    /// а не имя папки, — поэтому при установке снятого контейнера имя надо переписывать.
    /// </summary>
    public static class NameKey
    {
        /// <summary>Максимальная длина имени: длина кодируется одним байтом ASN.1 (короткая форма).</summary>
        public const int MaxNameLength = 125;

        /// <summary>Разобрать содержимое name.key. null — формат не распознан.</summary>
        public static string Parse(byte[] data)
        {
            if (data == null || data.Length < 5) return null;
            if (data[0] != 0x30 || data[2] != 0x16) return null;
            int len = data[3];
            if (len <= 0 || 4 + len > data.Length) return null;
            return Cp1251.GetString(data, 4, len);
        }

        /// <summary>Собрать содержимое name.key для заданного имени.</summary>
        public static byte[] Build(string name)
        {
            if (string.IsNullOrEmpty(name)) throw new ArgumentException("Пустое имя контейнера", nameof(name));
            byte[] text = Cp1251.GetBytes(name);
            if (text.Length > MaxNameLength)
                throw new ArgumentException($"Имя контейнера длиннее {MaxNameLength} символов", nameof(name));

            var result = new byte[4 + text.Length];
            result[0] = 0x30;
            result[1] = (byte)(text.Length + 2);
            result[2] = 0x16;
            result[3] = (byte)text.Length;
            Array.Copy(text, 0, result, 4, text.Length);
            return result;
        }
    }
}

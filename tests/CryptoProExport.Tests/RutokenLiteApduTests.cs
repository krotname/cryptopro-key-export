using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace CryptoProExport.Tests
{
    /// <summary>
    /// Чистая логика чтения контейнера с Рутокен Lite по APDU: разбор FCP, обрезка
    /// FF-набивки EF до чистого DER, имя из name.key и мягкая деградация без карты.
    /// Обращения к железу тут нет — оно проверяется e2e на живом токене (fw 9.02).
    /// </summary>
    public class RutokenLiteApduTests
    {
        [Fact]
        public void FcpSize_ReadsTag80FromTemplate()
        {
            // 62 24 80 02 0046 81 02 0066 82 02 0100 83 02 0B02 8A 01 05 ...
            var fcp = Convert.FromHexString("622480020046810200668202010083020B028A010586");
            Assert.Equal(0x46, RutokenLiteApdu.FcpSize(fcp));
        }

        [Fact]
        public void FcpSize_ReturnsMinusOneWhenAbsent()
        {
            Assert.Equal(-1, RutokenLiteApdu.FcpSize(new byte[] { 0x6A, 0x82 }));
        }

        [Fact]
        public void TrimDer_DropsFfPaddingToShortSequence()
        {
            // primary.key: SEQ{ OCTET STRING(32) } = 36 байт, файл добит FF до 70.
            var der = Convert.FromHexString("30220420" + new string('A', 64)); // 4 + 32 = 36
            var padded = new byte[70];
            Array.Copy(der, padded, der.Length);
            for (int i = der.Length; i < padded.Length; i++) padded[i] = 0xFF;
            Assert.Equal(36, RutokenLiteApdu.TrimDer(padded).Length);
        }

        [Fact]
        public void TrimDer_HandlesLongFormLength()
        {
            // header.key: 30 82 00 05 <5 байт> = 9 байт всего, плюс мусор в хвосте.
            var blob = Convert.FromHexString("3082000501020304FF" + "FFFFFF");
            Assert.Equal(9, RutokenLiteApdu.TrimDer(blob).Length);
        }

        [Fact]
        public void TrimDer_PassesThroughNonDer()
        {
            var raw = new byte[] { 0x6F, 0x10, 0x84 };
            Assert.Same(raw, RutokenLiteApdu.TrimDer(raw));
        }

        [Fact]
        public void ParseName_DecodesSequenceString()
        {
            // 30 Lf 16 Ln "abc" — IA5String «abc».
            var body = Encoding.ASCII.GetBytes("abc");
            var name = new byte[] { 0x30, (byte)(body.Length + 2), 0x16, (byte)body.Length };
            var full = new byte[name.Length + body.Length];
            Array.Copy(name, full, name.Length);
            Array.Copy(body, 0, full, name.Length, body.Length);
            Assert.Equal("abc", RutokenLiteApdu.ParseName(full));
        }

        [Fact]
        public void ParseName_ReturnsNullOnGarbage()
        {
            Assert.Null(RutokenLiteApdu.ParseName(new byte[] { 0x6A, 0x82 }));
            Assert.Null(RutokenLiteApdu.ParseName(null));
        }

        [Fact]
        public void ReadContainer_EmptyPin_ThrowsInsteadOfGuessing()
        {
            var lite = new RutokenLiteApdu();
            Assert.Throws<LiteApduException>(() =>
                lite.ReadContainer("Aktiv Rutoken lite 0", 0x0B, "", "unused"));
        }

        [Fact]
        public void ListContainers_UnknownReader_DegradesToException()
        {
            // Нет такого считывателя: PC/SC вернёт код ошибки, класс бросит LiteApduException
            // (а не уронит процесс) — как Pkcs11Token при отсутствии драйвера.
            var lite = new RutokenLiteApdu();
            Assert.Throws<LiteApduException>(() =>
                lite.ListContainers("no such reader 3E8F-nonexistent"));
        }

        [Fact]
        public void SaveFiles_InvalidRead_DoesNotDestroyPreviousBackup()
        {
            string dir = Path.Combine(Path.GetTempPath(), "cpx-lite-save-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            string oldHeader = Path.Combine(dir, "header.key");
            File.WriteAllBytes(oldHeader, new byte[] { 9, 9, 9 });
            try
            {
                var incomplete = new Dictionary<string, byte[]>
                {
                    ["header.key"] = new byte[] { 1 },
                    ["primary.key"] = new byte[] { 2 },
                    ["masks.key"] = new byte[] { 3 },
                    // name.key отсутствует: чтение карты не завершилось.
                };

                Assert.Throws<LiteApduException>(() => RutokenLiteApdu.SaveFiles(dir, incomplete));
                Assert.Equal(new byte[] { 9, 9, 9 }, File.ReadAllBytes(oldHeader));
            }
            finally { Directory.Delete(dir, recursive: true); }
        }

        [Fact]
        public void SaveFiles_RemovesStaleOptionalPairOnlyAfterCompleteRead()
        {
            string dir = Path.Combine(Path.GetTempPath(), "cpx-lite-save-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            File.WriteAllBytes(Path.Combine(dir, "masks2.key"), new byte[] { 8 });
            File.WriteAllBytes(Path.Combine(dir, "primary2.key"), new byte[] { 8 });
            try
            {
                var complete = new Dictionary<string, byte[]>
                {
                    ["name.key"] = new byte[] { 1 },
                    ["header.key"] = new byte[] { 2 },
                    ["primary.key"] = new byte[] { 3 },
                    ["masks.key"] = new byte[] { 4 },
                };

                RutokenLiteApdu.SaveFiles(dir, complete);

                Assert.Equal(new byte[] { 2 }, File.ReadAllBytes(Path.Combine(dir, "header.key")));
                Assert.False(File.Exists(Path.Combine(dir, "masks2.key")));
                Assert.False(File.Exists(Path.Combine(dir, "primary2.key")));
            }
            finally { Directory.Delete(dir, recursive: true); }
        }

        [Fact]
        public void SaveFiles_AcceptsSignatureOnlyContainer()
        {
            string dir = Path.Combine(Path.GetTempPath(), "cpx-lite-save-" + Guid.NewGuid().ToString("N"));
            try
            {
                var signatureOnly = new Dictionary<string, byte[]>
                {
                    ["name.key"] = new byte[] { 1 },
                    ["header.key"] = new byte[] { 2 },
                    ["primary2.key"] = new byte[] { 3 },
                    ["masks2.key"] = new byte[] { 4 },
                };

                RutokenLiteApdu.SaveFiles(dir, signatureOnly);

                Assert.True(File.Exists(Path.Combine(dir, "primary2.key")));
                Assert.True(File.Exists(Path.Combine(dir, "masks2.key")));
                Assert.False(File.Exists(Path.Combine(dir, "primary.key")));
                Assert.False(File.Exists(Path.Combine(dir, "masks.key")));
            }
            finally { if (Directory.Exists(dir)) Directory.Delete(dir, recursive: true); }
        }

        [Fact]
        public void SaveFiles_LockedOldFileRollsBackWholeContainer()
        {
            string dir = Path.Combine(Path.GetTempPath(), "cpx-lite-save-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            foreach (string file in new[] { "name.key", "header.key", "primary.key", "masks.key" })
                File.WriteAllBytes(Path.Combine(dir, file), new byte[] { 9 });
            var replacement = new Dictionary<string, byte[]>
            {
                ["name.key"] = new byte[] { 1 },
                ["header.key"] = new byte[] { 2 },
                ["primary.key"] = new byte[] { 3 },
                ["masks.key"] = new byte[] { 4 },
            };

            try
            {
                using (File.Open(Path.Combine(dir, "header.key"), FileMode.Open,
                                 FileAccess.Read, FileShare.None))
                    Assert.Throws<IOException>(() => RutokenLiteApdu.SaveFiles(dir, replacement));

                foreach (string file in new[] { "name.key", "header.key", "primary.key", "masks.key" })
                    Assert.Equal(new byte[] { 9 }, File.ReadAllBytes(Path.Combine(dir, file)));
            }
            finally { Directory.Delete(dir, recursive: true); }
        }

        [Fact]
        public void SaveFiles_PreservesNonContainerOutputsDuringSwap()
        {
            string dir = Path.Combine(Path.GetTempPath(), "cpx-lite-save-" + Guid.NewGuid().ToString("N"));
            string nested = Path.Combine(dir, "notes");
            Directory.CreateDirectory(nested);
            File.WriteAllText(Path.Combine(dir, "private.pem"), "secret");
            File.WriteAllText(Path.Combine(nested, "readme.txt"), "keep");
            var replacement = new Dictionary<string, byte[]>
            {
                ["name.key"] = new byte[] { 1 },
                ["header.key"] = new byte[] { 2 },
                ["primary.key"] = new byte[] { 3 },
                ["masks.key"] = new byte[] { 4 },
            };

            try
            {
                RutokenLiteApdu.SaveFiles(dir, replacement);

                Assert.Equal("secret", File.ReadAllText(Path.Combine(dir, "private.pem")));
                Assert.Equal("keep", File.ReadAllText(Path.Combine(dir, "notes", "readme.txt")));
            }
            finally { Directory.Delete(dir, recursive: true); }
        }

        [Fact]
        public void ReserveOutputDirectory_ConcurrentCallersGetDifferentFolders()
        {
            string root = Path.Combine(Path.GetTempPath(), "cpx-lite-reserve-" + Guid.NewGuid().ToString("N"));
            string first = null, second = null;
            try
            {
                Parallel.Invoke(
                    () => first = RutokenLiteApdu.ReserveOutputDirectory(root, "lite_01"),
                    () => second = RutokenLiteApdu.ReserveOutputDirectory(root, "lite_01"));

                Assert.NotEqual(first, second);
                Assert.True(Directory.Exists(first));
                Assert.True(Directory.Exists(second));
            }
            finally { if (Directory.Exists(root)) Directory.Delete(root, recursive: true); }
        }

        [Fact]
        public void ReserveOutputDirectory_UnsafeNameCannotEscapeParent()
        {
            string root = Path.Combine(Path.GetTempPath(), "cpx-lite-reserve-" + Guid.NewGuid().ToString("N"));
            try
            {
                string reserved = RutokenLiteApdu.ReserveOutputDirectory(root, @"..\outside");

                Assert.Equal(Path.GetFullPath(root), Path.GetDirectoryName(Path.GetFullPath(reserved)));
            }
            finally { if (Directory.Exists(root)) Directory.Delete(root, recursive: true); }
        }
    }
}

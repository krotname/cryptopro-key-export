using System;
using System.Text;
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
    }
}

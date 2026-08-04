using System;
using Xunit;

namespace CryptoProExport.Tests
{
    /// <summary>
    /// Кодировки — самое частое место ошибок в этом проекте: имена контейнеров приходят в cp1251,
    /// вывод консольных утилит КриптоПро — в cp866.
    /// </summary>
    public class CodecTests
    {
        [Theory]
        [InlineData("Андрей ФНС 26-27")]
        [InlineData("Ovcharenko_Andrey_280526")]
        [InlineData("Ёжик и ёлка № 5")]
        [InlineData("abc ЯяАа")]
        public void Cp1251_RoundTrip(string text)
        {
            byte[] bytes = Cp1251.GetBytes(text);
            Assert.Equal(text.Length, bytes.Length);
            Assert.Equal(text, Cp1251.GetString(bytes, 0, bytes.Length));
        }

        [Fact]
        public void Cp1251_KnownBytes()
        {
            Assert.Equal((byte)0xC0, Cp1251.GetBytes("А")[0]);
            Assert.Equal((byte)0xFF, Cp1251.GetBytes("я")[0]);
            Assert.Equal((byte)0xA8, Cp1251.GetBytes("Ё")[0]);
            Assert.Equal((byte)0xB8, Cp1251.GetBytes("ё")[0]);
            Assert.Equal((byte)0xB9, Cp1251.GetBytes("№")[0]);
        }

        [Fact]
        public void Cp1251_UnsupportedCharBecomesQuestionMark()
        {
            Assert.Equal((byte)'?', Cp1251.GetBytes("☃")[0]);
        }

        [Theory]
        [InlineData(0x80, 'А')]
        [InlineData(0x9F, 'Я')]
        [InlineData(0xA0, 'а')]
        [InlineData(0xAF, 'п')]
        [InlineData(0xE0, 'р')]
        [InlineData(0xEF, 'я')]
        [InlineData(0xF0, 'Ё')]
        [InlineData(0xF1, 'ё')]
        [InlineData(0xFC, '№')]
        public void Cp866_MapsCyrillic(int b, char expected)
        {
            Assert.Equal(expected.ToString(), Cp866.GetString(new[] { (byte)b }));
        }

        [Fact]
        public void Cp866_DecodesRealMessageFromP12Utility()
        {
            // «Операция успешно завершена.» — как её печатает p12utility
            byte[] bytes =
            {
                0x8E, 0xAF, 0xA5, 0xE0, 0xA0, 0xE6, 0xA8, 0xEF, 0x20,
                0xE3, 0xE1, 0xAF, 0xA5, 0xE8, 0xAD, 0xAE, 0x20,
                0xA7, 0xA0, 0xA2, 0xA5, 0xE0, 0xE8, 0xA5, 0xAD, 0xA0, 0x2E,
            };
            Assert.Equal("Операция успешно завершена.", Cp866.GetString(bytes));
        }

        [Fact]
        public void Cp866_KeepsAscii()
        {
            Assert.Equal("ExitCode: 0", Cp866.GetString(System.Text.Encoding.ASCII.GetBytes("ExitCode: 0")));
        }

        [Theory]
        [InlineData("cpxtest")]
        [InlineData("Андрей ФНС 26-27")]
        [InlineData("a")]
        public void NameKey_RoundTrip(string name)
        {
            byte[] data = NameKey.Build(name);
            Assert.Equal((byte)0x30, data[0]);
            Assert.Equal((byte)0x16, data[2]);
            Assert.Equal(data.Length - 4, (int)data[3]);
            Assert.Equal(name, NameKey.Parse(data));
        }

        [Fact]
        public void NameKey_MatchesLayoutWrittenByCryptoPro()
        {
            // Реальный name.key контейнера «cpxtest», созданного csptest
            byte[] expected = { 0x30, 0x09, 0x16, 0x07, 0x63, 0x70, 0x78, 0x74, 0x65, 0x73, 0x74 };
            Assert.Equal(expected, NameKey.Build("cpxtest"));
        }

        [Theory]
        [InlineData(new byte[0])]
        [InlineData(new byte[] { 0x30, 0x09, 0x17, 0x07, 1, 2, 3, 4, 5, 6, 7 })] // не IA5String
        [InlineData(new byte[] { 0x31, 0x09, 0x16, 0x07, 1, 2, 3, 4, 5, 6, 7 })] // не SEQUENCE
        [InlineData(new byte[] { 0x30, 0x09, 0x16, 0x40, 1, 2 })]                // длина выходит за буфер
        public void NameKey_ParseRejectsGarbage(byte[] data)
        {
            Assert.Null(NameKey.Parse(data));
        }

        [Fact]
        public void NameKey_ParseHandlesNull() => Assert.Null(NameKey.Parse(null));

        [Fact]
        public void NameKey_RejectsTooLongName()
        {
            Assert.Throws<ArgumentException>(() => NameKey.Build(new string('x', NameKey.MaxNameLength + 1)));
        }

        [Fact]
        public void NameKey_RejectsEmptyName()
        {
            Assert.Throws<ArgumentException>(() => NameKey.Build(""));
        }
    }
}

using System;
using Xunit;

namespace CryptoProExport.Tests
{
    /// <summary>
    /// Юнит-тесты MS_KEY K «АНГАРА» без железа: раскладка файловой памяти (DF/EF), разбор FCP,
    /// отбраковка пустых слотов и гейт семейства БИФИТ (MS_KEY K против iBank2Key).
    /// Живой цикл чтения и восстановления ключа проверен на носителе, разбор — docs/apdu/bifit-mskey.md.
    /// </summary>
    public sealed class MsKeyAngaraApduTests
    {
        [Theory]
        [InlineData(0, 0x01)]
        [InlineData(1, 0x11)]
        [InlineData(2, 0x21)]
        [InlineData(15, 0xF1)]
        public void ContainerBase_StepsBy0x10(int index, int expected)
        {
            Assert.Equal(expected, MsKeyAngaraApdu.ContainerBase(index));
        }

        [Theory]
        [InlineData(-1)]
        [InlineData(16)]
        public void ContainerBase_RejectsOutOfRange(int index)
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => MsKeyAngaraApdu.ContainerBase(index));
        }

        [Theory]
        // masks(+0), primary(+1), header(+2), name(+5) — относительно базы DF.
        [InlineData(0x01, 0x00, 0x01)]
        [InlineData(0x01, 0x01, 0x02)]
        [InlineData(0x01, 0x02, 0x03)]
        [InlineData(0x01, 0x05, 0x06)]
        [InlineData(0x11, 0x00, 0x11)]
        [InlineData(0x11, 0x05, 0x16)]
        public void EfId_IsDfBasePlusOffset(int df, int offset, int expected)
        {
            Assert.Equal((byte)expected, MsKeyAngaraApdu.EfId(df, offset));
        }

        [Fact]
        public void IsDerSequence_TrueOnlyForSequenceTag()
        {
            Assert.True(MsKeyAngaraApdu.IsDerSequence(new byte[] { 0x30, 0x0B, 0x16 }));
            Assert.False(MsKeyAngaraApdu.IsDerSequence(new byte[64]));          // пустой слот из нулей
            Assert.False(MsKeyAngaraApdu.IsDerSequence(new byte[] { 0x30 }));   // слишком короткий
            Assert.False(MsKeyAngaraApdu.IsDerSequence(null));
        }

        [Theory]
        // FCP-шаблон 0x62 { 0x80 = размер }: тег 80 длины 1 (name.key).
        [InlineData(new byte[] { 0x62, 0x03, 0x80, 0x01, 0x3E }, 0x3E)]
        // тег 80 длины 2 (header.key).
        [InlineData(new byte[] { 0x62, 0x04, 0x80, 0x02, 0x05, 0x28 }, 0x0528)]
        public void FcpSize_ReadsTag80(byte[] fcp, int expected)
        {
            Assert.Equal(expected, MsKeyAngaraApdu.FcpSize(fcp));
        }

        [Fact]
        public void FcpSize_MinusOneWhenNoTag80()
        {
            Assert.Equal(-1, MsKeyAngaraApdu.FcpSize(new byte[] { 0x62, 0x03, 0x82, 0x01, 0x00 }));
        }

        [Theory]
        [InlineData("BIFIT ANGARA 0", true)]
        [InlineData("bifit angara 1", true)]
        [InlineData("BIFIT iBank2Key 0", false)]   // другой носитель БИФИТ, у CSP контейнеров нет
        [InlineData("", false)]
        public void IsConfirmedMsKeyAngara_AcceptsOnlyAngaraReader(string reader, bool expected)
        {
            var token = new Pkcs11TokenInfo { Kind = RutokenKind.Bifit, Reader = reader };
            Assert.Equal(expected, DirectTokenApdu.IsConfirmedMsKeyAngara(token));
        }

        [Fact]
        public void IsConfirmedMsKeyAngara_FalseForOtherKinds()
        {
            var token = new Pkcs11TokenInfo { Kind = RutokenKind.Esmart, Reader = "BIFIT ANGARA 0" };
            Assert.False(DirectTokenApdu.IsConfirmedMsKeyAngara(token));
        }

        [Theory]
        [InlineData("BIFIT ANGARA 0")]
        [InlineData("BIFIT iBank2Key 0")]
        public void ReaderName_ClassifiesAsBifitFamily(string reader)
        {
            Assert.Equal(RutokenKind.Bifit, Pkcs11Token.ResolveReaderKind(reader, null));
        }

        [Fact]
        public void Bifit_IsSupportedByDirectApdu()
        {
            Assert.True(DirectTokenApdu.Supports(RutokenKind.Bifit));
        }
    }
}

using Xunit;

namespace CryptoProExport.Tests
{
    public sealed class JaCartaProSaltTests
    {
        [Theory]
        [InlineData(20)]
        [InlineData(43)]
        public void ServiceSalt_UsesTheFirstTwentyBytesOfEachKnownPayload(
            int payloadLength)
        {
            byte[] payload = new byte[payloadLength];
            for (int i = 0; i < payload.Length; i++) payload[i] = (byte)i;

            Assert.Equal(payload[..20], JaCartaProApdu.ExtractServiceSalt(payload));
        }

        [Theory]
        [InlineData(0)]
        [InlineData(19)]
        [InlineData(44)]
        public void ServiceSalt_RejectsUnknownPayloadLengths(int length)
        {
            Assert.False(JaCartaProApdu.IsSupportedServiceSaltLength(length));
        }
    }
}

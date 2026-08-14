using Xunit;

namespace CryptoProExport.Tests
{
    public sealed class ExportPipelineTests
    {
        [Fact]
        public void AllPresentKeysHandled_RequiresCertificateForEveryPresentKey()
        {
            var both = new RutokenContainer();
            both.Files["primary.key"] = new byte[] { 1 };
            both.Files["primary2.key"] = new byte[] { 2 };

            Assert.False(ExportPipeline.AllPresentKeysHandled(both, "exchange.cer", null));
            Assert.False(ExportPipeline.AllPresentKeysHandled(both, null, "signature.cer"));
            Assert.True(ExportPipeline.AllPresentKeysHandled(both, "exchange.cer", "signature.cer"));
        }

        [Fact]
        public void AllPresentKeysHandled_AllowsSingleKeyContainer()
        {
            var exchangeOnly = new RutokenContainer();
            exchangeOnly.Files["primary.key"] = new byte[] { 1 };

            Assert.True(ExportPipeline.AllPresentKeysHandled(exchangeOnly, "exchange.cer", null));
        }

        [Fact]
        public void AllPresentKeysHandled_RejectsContainerWithoutRecognizedKey()
        {
            Assert.False(ExportPipeline.AllPresentKeysHandled(new RutokenContainer(),
                                                               "exchange.cer", "signature.cer"));
        }
    }
}

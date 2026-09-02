using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Math;

namespace CryptoProExport
{
    /// <summary>Что делать с ключевыми файлами при сборке экспортируемой копии.</summary>
    public enum ExportableKeyFiles
    {
        /// <summary>
        /// Перенести <c>primary*.key</c> и <c>masks*.key</c> байт в байт. Единственный режим,
        /// который принимает КриптоПро CSP: в неэкспортируемой форме <c>primary.key</c> лежат два
        /// поля, и рабочее для CSP — первое (обёртка CSP), а не <c>[0]</c>, из которого читает
        /// закрытый ключ CSP-free экстрактор. Проверено на контейнере <c>csptest</c> (см. AGENTS).
        /// </summary>
        Preserve,

        /// <summary>
        /// Заново замаскировать оба ключа свежими mask/salt и записать <c>primary*.key</c> в
        /// однополевой экспортируемой форме — поведение Android-ядра, где контейнер собирается
        /// заново и CSP в цепочке нет. Ключ при этом восстанавливается тем же <c>d</c>, но
        /// КриптоПро такой контейнер в PFX не выгружает (обёртка CSP теряется).
        /// </summary>
        Remask,
    }

    /// <summary>
    /// Формирует новую экспортируемую копию файлового контейнера КриптоПро без CSP и p12utility.
    /// Оба ключа сначала независимо восстанавливаются и проверяются через <c>d·G</c>
    /// (<see cref="ContainerKeyExtractor"/>), в <c>header.key</c> взводится бит экспортируемости и
    /// пересчитывается имитовставка, а копия перед возвратом разбирается заново и сверяется с
    /// исходником — неверный пароль или порча заголовка обнаруживаются до записи на диск.
    ///
    /// Порт реализации из Android-ядра (<c>ExportableContainerBuilder.kt</c>): те же примитивы,
    /// тот же порядок полей, тот же расчёт MAC. Отличие одно и оно вынужденное — режим ключевых
    /// файлов, см. <see cref="ExportableKeyFiles"/>: на Android ключи всегда перемаскируются, а
    /// здесь по умолчанию переносятся как есть, иначе КриптоПро отказывается выгружать PFX
    /// (<c>NTE_BAD_KEY_STATE</c>).
    ///
    /// Исходная папка не изменяется: результат — отдельный набор файлов, который вызывающий
    /// записывает в новую папку (<see cref="ContainerFiles.WriteTo"/>).
    /// </summary>
    public static class ExportableContainerBuilder
    {
        /// <summary>Собрать экспортируемую копию контейнера.</summary>
        public static ContainerFiles Build(ContainerFiles files, string password = "",
            ExportableKeyFiles keyFiles = ExportableKeyFiles.Preserve) =>
            Build(files, password, keyFiles, bytes => RandomNumberGenerator.Fill(bytes));

        /// <summary>
        /// То же с внешним источником случайности — тесты подставляют детерминированный,
        /// чтобы сравнивать байты результата.
        /// </summary>
        internal static ContainerFiles Build(ContainerFiles files, string password,
            ExportableKeyFiles keyFiles, Action<byte[]> nextBytes)
        {
            if (files == null) throw new ArgumentNullException(nameof(files));
            password ??= "";

            List<ContainerKeyExtractor.ExtractedKey> sourceKeys = ContainerKeyExtractor.ExtractAll(files, password);
            try
            {
                var output = files.CopyMap();
                bool exchange = false, signature = false;
                foreach (var key in sourceKeys)
                {
                    if (key.Usage == ContainerKeyExtractor.KeyUsage.Exchange) exchange = true;
                    else signature = true;
                }
                output["header.key"] = CryptoProHeaderExportability.SetExportable(
                    files.Require("header.key"), exchange, signature);

                if (keyFiles == ExportableKeyFiles.Remask)
                    foreach (var key in sourceKeys)
                    {
                        bool isSignature = key.Usage == ContainerKeyExtractor.KeyUsage.Signature;
                        var (primary, masks) = RebuildPair(key.Result, password, nextBytes);
                        output[isSignature ? "primary2.key" : "primary.key"] = primary;
                        output[isSignature ? "masks2.key" : "masks.key"] = masks;
                    }

                var result = ContainerFiles.Of(output);

                // Копия проверяется до того, как вызывающий её сохранит: пересобранный контейнер
                // обязан отдавать ровно те же d и d·G, иначе ключ потерян молча.
                var verified = ContainerKeyExtractor.ExtractAll(result, password);
                try
                {
                    foreach (var source in sourceKeys)
                    {
                        ContainerKeyExtractor.Result copy = null;
                        foreach (var candidate in verified)
                            if (candidate.Usage == source.Usage) { copy = candidate.Result; break; }
                        if (copy == null)
                            throw Corrupt($"rebuilt container lost {UsageToken(source.Usage)} key");
                        if (!CryptographicOperations.FixedTimeEquals(source.Result.PrivateKey, copy.PrivateKey) ||
                            !copy.PublicX.AsSpan().SequenceEqual(source.Result.PublicX) ||
                            !copy.PublicY.AsSpan().SequenceEqual(source.Result.PublicY))
                            throw Corrupt($"rebuilt {UsageToken(source.Usage)} key failed d·G verification");
                    }
                }
                finally { ContainerKeyExtractor.Wipe(verified); }
                return result;
            }
            finally { ContainerKeyExtractor.Wipe(sourceKeys); }
        }

        /// <summary>Собрать <c>primary*.key</c> и <c>masks*.key</c> для той же точки d·G, но со свежей маской.</summary>
        private static (byte[] Primary, byte[] Masks) RebuildPair(
            ContainerKeyExtractor.Result key, string password, Action<byte[]> nextBytes)
        {
            var domain = ECGost3410NamedCurves.GetByOid(new DerObjectIdentifier(key.CurveOid))
                ?? throw new ContainerKeyException(Strings.Format("err.extract.curve", key.CurveOid));
            BigInteger q = domain.N;

            var random = new byte[32];
            BigInteger mask;
            do
            {
                nextBytes(random);
                mask = new BigInteger(1, random).Mod(q);
            } while (mask.SignValue == 0);

            var salt = new byte[12];
            nextBytes(salt);
            byte[] maskBytes = ContainerKeyExtractor.Reverse(ContainerKeyExtractor.Pad32(mask));
            byte[] primaryPlain = ContainerKeyExtractor.Reverse(ContainerKeyExtractor.Pad32(
                new BigInteger(1, key.PrivateKey).Multiply(mask).Mod(q)));
            byte[] storageKey = GostContainerCrypto.DeriveStorageKey(password, salt);
            byte[] primaryEncrypted = GostContainerCrypto.EcbEncrypt(storageKey, primaryPlain);
            byte[] maskMac = GostContainerCrypto.MaskMac(maskBytes, salt);
            try
            {
                byte[] primary = new DerSequence(new DerOctetString(primaryEncrypted)).GetEncoded(Asn1Encodable.Der);
                byte[] masks = new DerSequence(
                    new DerOctetString(maskBytes),
                    new DerOctetString(salt),
                    new DerOctetString(maskMac)).GetEncoded(Asn1Encodable.Der);
                return (primary, masks);
            }
            finally
            {
                Array.Clear(random, 0, random.Length);
                Array.Clear(salt, 0, salt.Length);
                Array.Clear(maskBytes, 0, maskBytes.Length);
                Array.Clear(primaryPlain, 0, primaryPlain.Length);
                Array.Clear(storageKey, 0, storageKey.Length);
                Array.Clear(primaryEncrypted, 0, primaryEncrypted.Length);
                Array.Clear(maskMac, 0, maskMac.Length);
            }
        }

        /// <summary>Латинский токен назначения ключа для технического хвоста сообщения об ошибке.</summary>
        private static string UsageToken(ContainerKeyExtractor.KeyUsage usage) =>
            usage == ContainerKeyExtractor.KeyUsage.Signature ? "signature" : "exchange";

        private static ContainerKeyException Corrupt(string detail) =>
            new ContainerKeyException(Strings.Format("err.extract.corrupt", detail));
    }

    /// <summary>
    /// Строгая правка только двух битов экспортируемости и четырёхбайтового MAC <c>header.key</c>.
    /// Схема и MAC сверены с MIT-реализацией <c>@li0ard/cpfx</c> 0.1.2; в отличие от неё здесь
    /// проверяется исходный MAC и, если контейнер двухключевой, обновляются обе пары.
    /// </summary>
    public static class CryptoProHeaderExportability
    {
        /// <summary>Бит «ключ можно экспортировать» в первом байте атрибутов ключа.</summary>
        private const int ExportableMask = 0x80;

        /// <summary>
        /// Вернуть <c>header.key</c>, в котором взведён бит экспортируемости у нужных ключей и
        /// пересчитана имитовставка. Исходный MAC обязан сойтись: править заголовок, который и так
        /// не проходит проверку целостности, значит превратить непонятную ошибку в тихую порчу.
        /// </summary>
        public static byte[] SetExportable(byte[] header, bool exchange, bool signature)
        {
            var root = ParseSequence(header, "header.key");
            if (root.Count != 2) throw Corrupt("header.key root must contain content and MAC");
            if (root[0] is not Asn1Sequence content) throw Corrupt("header.key content is not SEQUENCE");
            byte[] storedMac = MacOf(root);
            byte[] contentDer = content.GetEncoded(Asn1Encodable.Der);
            if (!storedMac.AsSpan().SequenceEqual(GostContainerCrypto.ContainerMac(contentDer)))
                throw Corrupt("header.key MAC mismatch");

            Asn1Sequence changed = RewriteContent(content, exchange, signature);
            byte[] changedDer = changed.GetEncoded(Asn1Encodable.Der);
            return new DerSequence(changed, new DerOctetString(GostContainerCrypto.ContainerMac(changedDer)))
                .GetEncoded(Asn1Encodable.Der);
        }

        /// <summary>Проверить MAC заголовка и требуемые флаги — после сборки копии или чтения с носителя.</summary>
        public static void RequireExportable(byte[] header, bool exchange, bool signature)
        {
            var root = ParseSequence(header, "header.key");
            if (root.Count != 2) throw Corrupt("header.key root must contain content and MAC");
            if (root[0] is not Asn1Sequence content) throw Corrupt("header.key content is not SEQUENCE");
            byte[] storedMac = MacOf(root);
            if (!storedMac.AsSpan().SequenceEqual(
                    GostContainerCrypto.ContainerMac(content.GetEncoded(Asn1Encodable.Der))))
                throw Corrupt("header.key MAC mismatch");

            int outerAttributes = OuterAttributesIndex(content);
            Asn1Sequence primary = PrimaryParameters(content, outerAttributes);
            Asn1Sequence secondary = SecondaryParameters(content, out _);

            if ((exchange || (signature && secondary == null)) && !IsExportable(primary))
                throw Corrupt("header.key primary key is not exportable");
            if (signature && secondary != null && !IsExportable(secondary))
                throw Corrupt("header.key secondary key is not exportable");
        }

        private static Asn1Sequence RewriteContent(Asn1Sequence content, bool exchange, bool signature)
        {
            var elements = new Asn1Encodable[content.Count];
            for (int i = 0; i < content.Count; i++) elements[i] = content[i];

            int outerAttributes = OuterAttributesIndex(content);
            int primaryIndex = PrimaryParametersIndex(content, outerAttributes);
            Asn1Sequence secondary = SecondaryParameters(content, out int secondaryIndex);

            // Некоторые контейнеры содержат primary2/masks2, но отдельного поля [4] в header нет:
            // обе файловые пары используют единственный набор параметров. В таком варианте флаг
            // первичного набора должен быть включён и для signature-only/дублированной пары.
            elements[primaryIndex] = RewritePrivateKeyParameters(
                (Asn1Sequence)elements[primaryIndex].ToAsn1Object(),
                exchange || (signature && secondary == null));
            if (secondary != null)
                elements[secondaryIndex] = new DerTaggedObject(
                    false, 4, RewritePrivateKeyParameters(secondary, signature));
            return new DerSequence(elements);
        }

        private static Asn1Sequence RewritePrivateKeyParameters(Asn1Sequence parameters, bool makeExportable)
        {
            byte[] bytes = AttributeBytes(parameters, out DerBitString attributes);
            int padBits = attributes.PadBits;
            if (makeExportable)
            {
                if (bytes.Length == 0)
                {
                    // Пустой BIT STRING — «атрибутов нет» (так выглядит ключ подписи контейнера,
                    // созданного csptest). Место под бит надо создать, и в минимальной DER-форме,
                    // которой пользуется сам КриптоПро: значимых битов ровно один.
                    bytes = new byte[] { ExportableMask };
                    padBits = 7;
                }
                else
                {
                    bytes[0] = (byte)(bytes[0] | ExportableMask);
                }
            }
            var elements = new Asn1Encodable[parameters.Count];
            elements[0] = new DerBitString(bytes, padBits);
            for (int i = 1; i < parameters.Count; i++) elements[i] = parameters[i];
            return new DerSequence(elements);
        }

        private static bool IsExportable(Asn1Sequence parameters)
        {
            byte[] bytes = AttributeBytes(parameters, out _);
            return bytes.Length > 0 && (bytes[0] & ExportableMask) != 0;
        }

        /// <summary>
        /// Байты BIT STRING атрибутов ключа — в первом из них и лежит бит экспортируемости.
        /// Массив бывает пустым: контейнер, у которого все атрибуты ключа по умолчанию, хранит
        /// <c>03 01 00</c> (ноль значимых битов), и это не повреждение.
        /// </summary>
        private static byte[] AttributeBytes(Asn1Sequence parameters, out DerBitString attributes)
        {
            if (parameters.Count < 1) throw Corrupt("empty private key parameters");
            attributes = parameters[0].ToAsn1Object() as DerBitString
                ?? throw Corrupt("private key attributes are not BIT STRING");
            return attributes.GetBytes();
        }

        /// <summary>Атрибуты самого контейнера — первый BIT STRING содержимого заголовка.</summary>
        private static int OuterAttributesIndex(Asn1Sequence content)
        {
            for (int i = 0; i < content.Count; i++)
                if (content[i].ToAsn1Object() is DerBitString) return i;
            throw Corrupt("header.key has no container attributes");
        }

        private static int PrimaryParametersIndex(Asn1Sequence content, int outerAttributes)
        {
            for (int i = outerAttributes + 1; i < content.Count; i++)
                if (content[i].ToAsn1Object() is Asn1Sequence) return i;
            throw Corrupt("header.key has no primary key parameters");
        }

        private static Asn1Sequence PrimaryParameters(Asn1Sequence content, int outerAttributes) =>
            (Asn1Sequence)content[PrimaryParametersIndex(content, outerAttributes)].ToAsn1Object();

        /// <summary>Параметры второго ключа — неявный контекстный тег [4], или <c>null</c>, если его нет.</summary>
        private static Asn1Sequence SecondaryParameters(Asn1Sequence content, out int index)
        {
            for (int i = 0; i < content.Count; i++)
            {
                if (content[i].ToAsn1Object() is not Asn1TaggedObject tagged) continue;
                if (tagged.TagClass != Asn1Tags.ContextSpecific || tagged.TagNo != 4) continue;
                index = i;
                try { return Asn1Sequence.GetInstance(tagged, false); }
                catch (Exception) { throw Corrupt("header.key secondary key parameters are malformed"); }
            }
            index = -1;
            return null;
        }

        private static byte[] MacOf(Asn1Sequence root)
        {
            byte[] mac;
            try { mac = Asn1OctetString.GetInstance(root[1]).GetOctets(); }
            catch (Exception) { throw Corrupt("header.key MAC is not OCTET STRING"); }
            if (mac.Length != 4) throw Corrupt("header.key MAC must be 4 bytes");
            return mac;
        }

        private static Asn1Sequence ParseSequence(byte[] der, string name)
        {
            if (der == null) throw Corrupt($"{name} is missing");
            try { return (Asn1Sequence)Asn1Object.FromByteArray(RutokenLiteApdu.TrimDer(der)); }
            catch (Exception e) { throw Corrupt($"{name} ASN.1: {e.Message}"); }
        }

        private static ContainerKeyException Corrupt(string detail) =>
            new ContainerKeyException(Strings.Format("err.extract.corrupt", detail));
    }
}

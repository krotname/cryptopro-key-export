using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;

namespace CryptoProExport
{
    /// <summary>Проверенный результат восстановления файлового контейнера из PKCS#8.</summary>
    public sealed class Pkcs8ContainerRestoreResult
    {
        internal Pkcs8ContainerRestoreResult(string directory, string name, string curveOid,
            byte[] publicX)
        {
            Directory = directory;
            ContainerName = name;
            CurveOid = curveOid;
            PublicX = publicX;
        }

        /// <summary>Абсолютный путь опубликованной папки-контейнера.</summary>
        public string Directory { get; }

        /// <summary>Имя внутри <c>name.key</c>.</summary>
        public string ContainerName { get; }

        /// <summary>OID набора параметров кривой.</summary>
        public string CurveOid { get; }

        /// <summary>Координата X проверенного открытого ключа, 32 байта big-endian.</summary>
        public byte[] PublicX { get; }
    }

    /// <summary>
    /// CSP-free восстановление одноключевого файлового контейнера КриптоПро из незашифрованного
    /// PKCS#8 и соответствующего сертификата X.509. Поддерживается ровно ГОСТ Р 34.10-2012/256,
    /// который выдаёт <see cref="GostKeyExport"/>. До сборки проверяются алгоритм, кривая и
    /// равенство <c>d·G</c> открытому ключу сертификата.
    /// </summary>
    public static class Pkcs8ContainerRestore
    {
        private const string Gost3410_2012_256 = "1.2.643.7.1.1.1.1";
        private const string DigestParamSet256 = "1.2.643.7.1.1.2.2";

        /// <summary>
        /// Собрать проверенный контейнер в памяти. Вход может быть DER или PEM
        /// (<c>PRIVATE KEY</c> / <c>CERTIFICATE</c>); зашифрованный PKCS#8 не принимается.
        /// </summary>
        public static ContainerFiles Build(byte[] pkcs8OrPem, byte[] certificateDerOrPem,
            string containerName, string password = "")
        {
            ParsedInput input = Parse(pkcs8OrPem, certificateDerOrPem);
            try { return Build(input, containerName, password ?? "", bytes => RandomNumberGenerator.Fill(bytes)); }
            finally { input.Wipe(); }
        }

        /// <summary>
        /// Восстановить контейнер в новой папке. Сначала он строится в памяти, затем во временной
        /// соседней папке повторно читается <see cref="ContainerKeyExtractor"/> и только после
        /// этого одним переименованием публикуется под конечным именем.
        /// </summary>
        public static Pkcs8ContainerRestoreResult RestoreToDirectory(string keyPath,
            string certificatePath, string targetDirectory, string password = "")
        {
            if (keyPath == null) throw new ArgumentNullException(nameof(keyPath));
            if (certificatePath == null) throw new ArgumentNullException(nameof(certificatePath));
            if (targetDirectory == null) throw new ArgumentNullException(nameof(targetDirectory));

            string target = Path.GetFullPath(targetDirectory);
            if (Directory.Exists(target) || File.Exists(target))
                throw new ContainerKeyException(Strings.Format("err.restore.target", target));

            string name = Path.GetFileName(Path.TrimEndingDirectorySeparator(target));
            if (string.IsNullOrEmpty(name))
                throw new ContainerKeyException(Strings.Format("err.restore.target", target));

            byte[] keyBytes = null;
            byte[] certificateBytes = null;
            ParsedInput input = null;
            ContainerFiles files = null;
            string temporary = null;
            try
            {
                keyBytes = File.ReadAllBytes(keyPath);
                certificateBytes = File.ReadAllBytes(certificatePath);
                input = Parse(keyBytes, certificateBytes);
                files = Build(input, name, password ?? "", bytes => RandomNumberGenerator.Fill(bytes));

                string parent = Path.GetDirectoryName(target);
                if (string.IsNullOrEmpty(parent))
                    throw new ContainerKeyException(Strings.Format("err.restore.target", target));
                Directory.CreateDirectory(parent);
                temporary = ReserveTemporaryDirectory(parent, name);
                files.WriteTo(temporary);
                Verify(temporary, password ?? "", input);

                // Повторная проверка защищает и от гонки: конечный путь не перезаписывается.
                if (Directory.Exists(target) || File.Exists(target))
                    throw new ContainerKeyException(Strings.Format("err.restore.target", target));
                Directory.Move(temporary, target);
                temporary = null;
                return new Pkcs8ContainerRestoreResult(target, name, input.CurveOid,
                    (byte[])input.PublicX.Clone());
            }
            finally
            {
                if (temporary != null) DeleteTemporaryDirectory(temporary);
                files?.WipeKeyMaterial();
                input?.Wipe();
                Zero(keyBytes);
            }
        }

        private static ContainerFiles Build(ParsedInput input, string containerName, string password,
            Action<byte[]> nextBytes)
        {
            if (string.IsNullOrEmpty(containerName))
                throw new ArgumentException(Strings.Get("err.name.empty"), nameof(containerName));

            var domain = ECGost3410NamedCurves.GetByOid(new DerObjectIdentifier(input.CurveOid))
                ?? throw new ContainerKeyException(Strings.Format("err.extract.curve", input.CurveOid));
            BigInteger q = domain.N;
            byte[] random = new byte[32];
            byte[] salt = new byte[12];
            byte[] maskBytes = null;
            byte[] primaryPlain = null;
            byte[] storageKey = null;
            byte[] primaryEncrypted = null;
            byte[] maskMac = null;
            ContainerFiles result = null;
            try
            {
                BigInteger mask;
                do
                {
                    nextBytes(random);
                    mask = new BigInteger(1, random).Mod(q);
                } while (mask.SignValue == 0);

                nextBytes(salt);
                maskBytes = ContainerKeyExtractor.Reverse(ContainerKeyExtractor.Pad32(mask));
                primaryPlain = ContainerKeyExtractor.Reverse(ContainerKeyExtractor.Pad32(
                    input.D.Multiply(mask).Mod(q)));
                storageKey = GostContainerCrypto.DeriveStorageKey(password, salt);
                primaryEncrypted = GostContainerCrypto.EcbEncrypt(storageKey, primaryPlain);
                maskMac = GostContainerCrypto.MaskMac(maskBytes, salt);

                var algorithm = new DerSequence(
                    new DerObjectIdentifier(Gost3410_2012_256),
                    new DerSequence(new DerObjectIdentifier(input.CurveOid),
                        new DerObjectIdentifier(DigestParamSet256)));
                var keyParameters = new DerSequence(
                    new DerBitString(new byte[] { 0x80 }, 7),
                    new DerTaggedObject(false, 0, algorithm));
                byte[] fingerprint = new byte[8];
                byte[] xLittleEndian = ContainerKeyExtractor.Reverse(input.PublicX);
                Array.Copy(xLittleEndian, fingerprint, fingerprint.Length);

                var content = new DerSequence(
                    new DerBitString(new byte[] { 0x00 }),
                    keyParameters,
                    new DerTaggedObject(false, 5, new DerOctetString(input.Certificate)),
                    new DerTaggedObject(false, 10, new DerOctetString(fingerprint)));
                byte[] contentDer = content.GetEncoded(Asn1Encodable.Der);
                byte[] header = new DerSequence(content,
                    new DerOctetString(GostContainerCrypto.ContainerMac(contentDer)))
                    .GetEncoded(Asn1Encodable.Der);

                result = ContainerFiles.Of(new System.Collections.Generic.Dictionary<string, byte[]>(
                    StringComparer.OrdinalIgnoreCase)
                {
                    ["primary.key"] = new DerSequence(new DerOctetString(primaryEncrypted))
                        .GetEncoded(Asn1Encodable.Der),
                    ["masks.key"] = new DerSequence(
                        new DerOctetString(maskBytes), new DerOctetString(salt),
                        new DerOctetString(maskMac)).GetEncoded(Asn1Encodable.Der),
                    ["header.key"] = header,
                    ["name.key"] = NameKey.Build(containerName),
                });

                Verify(result, password, input);
                CryptoProHeaderExportability.RequireExportable(result.Require("header.key"),
                    exchange: true, signature: false);
                return result;
            }
            catch
            {
                result?.WipeKeyMaterial();
                throw;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(random);
                CryptographicOperations.ZeroMemory(salt);
                Zero(maskBytes);
                Zero(primaryPlain);
                Zero(storageKey);
                Zero(primaryEncrypted);
                Zero(maskMac);
            }
        }

        private static ParsedInput Parse(byte[] pkcs8OrPem, byte[] certificateDerOrPem)
        {
            if (pkcs8OrPem == null) throw new ArgumentNullException(nameof(pkcs8OrPem));
            if (certificateDerOrPem == null) throw new ArgumentNullException(nameof(certificateDerOrPem));

            byte[] keyDer = null;
            byte[] certificateDer = null;
            byte[] privateKey = null;
            try
            {
                keyDer = Decode(pkcs8OrPem, "PRIVATE KEY", key: true);
                certificateDer = Decode(certificateDerOrPem, "CERTIFICATE", key: false);
                PrivateKeyInfo keyInfo;
                try { keyInfo = PrivateKeyInfo.GetInstance(Asn1Object.FromByteArray(keyDer)); }
                catch (Exception e) { throw InputError("err.restore.input", e.Message); }

                AlgorithmIdentifier keyAlgorithm = keyInfo.PrivateKeyAlgorithm;
                RequireAlgorithm(keyAlgorithm, "PKCS#8");
                string keyCurve = CurveFrom(keyAlgorithm, "PKCS#8");
                try
                {
                    privateKey = Asn1OctetString.GetInstance(keyInfo.ParsePrivateKey()).GetOctets();
                }
                catch (Exception e) { throw InputError("err.restore.input", e.Message); }
                if (privateKey.Length != 32)
                    throw InputError("err.restore.input", $"private key is {privateKey.Length} bytes, expected 32");

                X509CertificateStructure certificate;
                try { certificate = X509CertificateStructure.GetInstance(Asn1Object.FromByteArray(certificateDer)); }
                catch (Exception e) { throw InputError("err.restore.certificate", e.Message); }
                RequireAlgorithm(certificate.SubjectPublicKeyInfo.Algorithm, "certificate");
                string certificateCurve = CurveFrom(certificate.SubjectPublicKeyInfo.Algorithm, "certificate");
                if (!string.Equals(keyCurve, certificateCurve, StringComparison.Ordinal))
                    throw new ContainerKeyException(Strings.Get("err.restore.curve.mismatch"));

                var domain = ECGost3410NamedCurves.GetByOid(new DerObjectIdentifier(keyCurve));
                if (domain == null)
                    throw new ContainerKeyException(Strings.Format("err.extract.curve", keyCurve));
                BigInteger d = new BigInteger(1, ContainerKeyExtractor.Reverse(privateKey));
                if (d.SignValue == 0 || d.CompareTo(domain.N) >= 0)
                    throw InputError("err.restore.input", "private scalar is outside curve order");

                byte[] certificatePublic = ContainerKeyExtractor.CertificatePublicKey(certificateDer);
                if (certificatePublic == null)
                    throw InputError("err.restore.certificate", "GOST 2012-256 public key is not 64 bytes");
                Org.BouncyCastle.Math.EC.ECPoint point = domain.G.Multiply(d).Normalize();
                byte[] x = ContainerKeyExtractor.Pad32(point.AffineXCoord.ToBigInteger());
                byte[] y = ContainerKeyExtractor.Pad32(point.AffineYCoord.ToBigInteger());
                byte[] expectedPublic = new byte[64];
                Array.Copy(ContainerKeyExtractor.Reverse(x), 0, expectedPublic, 0, 32);
                Array.Copy(ContainerKeyExtractor.Reverse(y), 0, expectedPublic, 32, 32);
                if (!CryptographicOperations.FixedTimeEquals(expectedPublic, certificatePublic))
                    throw new ContainerKeyException(Strings.Get("err.restore.key.mismatch"));

                return new ParsedInput(d, keyCurve, x, y, certificateDer);
            }
            finally
            {
                Zero(privateKey);
                Zero(keyDer);
            }
        }

        private static void RequireAlgorithm(AlgorithmIdentifier algorithm, string source)
        {
            string oid = algorithm?.Algorithm?.Id ?? "-";
            if (!string.Equals(oid, Gost3410_2012_256, StringComparison.Ordinal))
                throw new ContainerKeyException(Strings.Format("err.restore.algorithm", source, oid));
        }

        private static string CurveFrom(AlgorithmIdentifier algorithm, string source)
        {
            try
            {
                var parameters = Asn1Sequence.GetInstance(algorithm.Parameters);
                if (parameters.Count < 2)
                    throw new InvalidDataException("algorithm parameters are incomplete");
                string curve = DerObjectIdentifier.GetInstance(parameters[0]).Id;
                string digest = DerObjectIdentifier.GetInstance(parameters[1]).Id;
                if (!string.Equals(digest, DigestParamSet256, StringComparison.Ordinal))
                    throw new InvalidDataException("digest parameter set is unsupported");
                return curve;
            }
            catch (ContainerKeyException) { throw; }
            catch (Exception e)
            {
                throw InputError("err.restore.parameters", $"{source}: {e.Message}");
            }
        }

        private static byte[] Decode(byte[] input, string expectedLabel, bool key)
        {
            byte[] copy = (byte[])input.Clone();
            string text;
            try { text = new UTF8Encoding(false, true).GetString(copy).Trim(); }
            catch (DecoderFallbackException) { return copy; }
            if (!text.StartsWith("-----BEGIN ", StringComparison.Ordinal)) return copy;

            if (key && text.StartsWith("-----BEGIN ENCRYPTED PRIVATE KEY-----", StringComparison.Ordinal))
            {
                CryptographicOperations.ZeroMemory(copy);
                throw new ContainerKeyException(Strings.Get("err.restore.encrypted"));
            }

            string begin = $"-----BEGIN {expectedLabel}-----";
            string end = $"-----END {expectedLabel}-----";
            int beginAt = text.IndexOf(begin, StringComparison.Ordinal);
            int endAt = text.IndexOf(end, StringComparison.Ordinal);
            if (beginAt != 0 || endAt <= begin.Length ||
                text.Substring(endAt + end.Length).Trim().Length != 0)
            {
                CryptographicOperations.ZeroMemory(copy);
                throw InputError(key ? "err.restore.input" : "err.restore.certificate",
                    $"expected PEM label {expectedLabel}");
            }

            string payload = text.Substring(begin.Length, endAt - begin.Length)
                .Replace("\r", "", StringComparison.Ordinal)
                .Replace("\n", "", StringComparison.Ordinal)
                .Replace(" ", "", StringComparison.Ordinal)
                .Replace("\t", "", StringComparison.Ordinal);
            try
            {
                byte[] der = Convert.FromBase64String(payload);
                CryptographicOperations.ZeroMemory(copy);
                return der;
            }
            catch (FormatException e)
            {
                CryptographicOperations.ZeroMemory(copy);
                throw InputError(key ? "err.restore.input" : "err.restore.certificate", e.Message);
            }
        }

        private static void Verify(ContainerFiles files, string password, ParsedInput input)
        {
            ContainerKeyExtractor.Result restored = ContainerKeyExtractor.Extract(files, password);
            try { RequireSameKey(restored, input); }
            finally { Zero(restored.PrivateKey); }
        }

        private static void Verify(string directory, string password, ParsedInput input)
        {
            ContainerKeyExtractor.Result restored = ContainerKeyExtractor.Extract(directory, password);
            try { RequireSameKey(restored, input); }
            finally { Zero(restored.PrivateKey); }
        }

        private static void RequireSameKey(ContainerKeyExtractor.Result restored, ParsedInput input)
        {
            byte[] expected = ContainerKeyExtractor.Pad32(input.D);
            try
            {
                if (!CryptographicOperations.FixedTimeEquals(expected, restored.PrivateKey) ||
                    !restored.PublicX.AsSpan().SequenceEqual(input.PublicX) ||
                    !restored.PublicY.AsSpan().SequenceEqual(input.PublicY) ||
                    !string.Equals(restored.CurveOid, input.CurveOid, StringComparison.Ordinal) ||
                    restored.Certificate == null)
                    throw new ContainerKeyException(Strings.Get("err.restore.verify"));
            }
            finally { CryptographicOperations.ZeroMemory(expected); }
        }

        private static string ReserveTemporaryDirectory(string parent, string targetName)
        {
            for (int i = 0; i < 16; i++)
            {
                string candidate = Path.Combine(parent,
                    $".{targetName}.restore-{Guid.NewGuid():N}.tmp");
                if (Directory.Exists(candidate) || File.Exists(candidate)) continue;
                Directory.CreateDirectory(candidate);
                if ((File.GetAttributes(candidate) & FileAttributes.ReparsePoint) != 0)
                    throw new IOException("Temporary container path is a reparse point.");
                return candidate;
            }
            throw new IOException("Cannot reserve a temporary container directory.");
        }

        private static void DeleteTemporaryDirectory(string directory)
        {
            if (!Directory.Exists(directory)) return;
            if ((File.GetAttributes(directory) & FileAttributes.ReparsePoint) != 0)
                throw new IOException("Temporary container path became a reparse point.");

            // Удаляем только файлы, которые могли создать сами. Рекурсивное удаление здесь
            // превратило бы гонку в возможность удалить подменённое содержимое. Если другой
            // процесс добавил что-либо ещё, Directory.Delete честно упадёт и покажет хвост.
            foreach (string name in ContainerFiles.Names)
            {
                string path = Path.Combine(directory, name);
                if (File.Exists(path)) File.Delete(path);
            }
            Directory.Delete(directory, recursive: false);
        }

        private static ContainerKeyException InputError(string key, string detail) =>
            new ContainerKeyException(Strings.Format(key, detail));

        private static void Zero(byte[] value)
        {
            if (value != null) CryptographicOperations.ZeroMemory(value);
        }

        private sealed class ParsedInput
        {
            internal ParsedInput(BigInteger d, string curveOid, byte[] x, byte[] y, byte[] certificate)
            {
                D = d;
                CurveOid = curveOid;
                PublicX = x;
                PublicY = y;
                Certificate = certificate;
            }

            internal BigInteger D { get; }
            internal string CurveOid { get; }
            internal byte[] PublicX { get; }
            internal byte[] PublicY { get; }
            internal byte[] Certificate { get; }

            internal void Wipe()
            {
                Zero(PublicX);
                Zero(PublicY);
            }
        }
    }
}

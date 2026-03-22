using Oci.Common.Auth;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;

namespace OciSecurityListMonitor;

public class StringPrivateKeySupplier : ISupplier<RsaKeyParameters>
{
    private readonly string _pem;

    public StringPrivateKeySupplier(string pem)
    {
        _pem = pem;
    }

    public RsaKeyParameters GetKey()
    {
        using var reader = new StringReader(_pem);
        var pemReader = new PemReader(reader);
        var obj = pemReader.ReadObject();

        return obj switch
        {
            AsymmetricCipherKeyPair pair => (RsaPrivateCrtKeyParameters)pair.Private,
            RsaKeyParameters key => key,
            _ => throw new InvalidOperationException("PEMから秘密鍵を読み込めません")
        };
    }
}
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

// Gera par de chaves
using RSA rsa = RSA.Create();
Console.WriteLine("Chave Privada:");
Console.WriteLine(PegaPrivateKey(rsa));

string publicKey = PegarPublicKey(rsa);
Console.WriteLine("\nChave Pública:");
Console.WriteLine(publicKey);

// Assinatura do token com a chave privada
var token = GerarTokenAssinado(rsa);
Console.WriteLine("\nToken:");
Console.WriteLine(token.ToString());

// Verificação da assinatura com a chave publica
bool eValido = VerificarAssinatura(token, rsa);
Console.WriteLine($"\nToken valido: {eValido}");
    

static string GerarTokenAssinado(RSA rsa)
{
    var tokenHandler = new JwtSecurityTokenHandler();
    var key = new RsaSecurityKey(rsa);
    var tokenDescriptor = new SecurityTokenDescriptor
    {
        Subject = new ClaimsIdentity(new[] { new Claim("usuario", "examploUsuario") }),
        Expires = DateTime.UtcNow.AddHours(1),
        SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256Signature)
    };
    var token = tokenHandler.CreateToken(tokenDescriptor);
    return tokenHandler.WriteToken(token);
}

static bool VerificarAssinatura(string token, RSA rsa)
{
    var tokenHandler = new JwtSecurityTokenHandler();
    var validationParameters = new TokenValidationParameters
    {
        IssuerSigningKey = new RsaSecurityKey(rsa),
        ValidateIssuerSigningKey = true,
        ValidateIssuer = true,
        ValidateAudience = false 
    };

    try
    {
         SecurityToken validatedToken;
         tokenHandler.ValidateToken(token, validationParameters, out validatedToken);
         return true;
    }
    catch (SecurityTokenException)
    {
         return false;
    }
}

static string PegarPublicKey(RSA rsa)
{
    RSAParameters publicKeyParams = rsa.ExportParameters(false);
    RSAParameters publicKeyOnly = new RSAParameters
    {
        Modulus = publicKeyParams.Modulus,
        Exponent = publicKeyParams.Exponent
    };

    using RSA rsaPublicOnly = RSA.Create();
    rsaPublicOnly.ImportParameters(publicKeyOnly);
    return $"-----PUBLIC KEY-----\n{Convert.ToBase64String(rsaPublicOnly.ExportSubjectPublicKeyInfo())}\n-----FIM PUBLIC KEY-----";
}

static string PegaPrivateKey(RSA rsa)
{
    RSAParameters privateKeyParams = rsa.ExportParameters(true);
    return $"Modulus: {Convert.ToBase64String(privateKeyParams.Modulus)}\nExponent: {Convert.ToBase64String(privateKeyParams.Exponent)}\nD: {Convert.ToBase64String(privateKeyParams.D)}\nP: {Convert.ToBase64String(privateKeyParams.P)}\nQ: {Convert.ToBase64String(privateKeyParams.Q)}\nDP: {Convert.ToBase64String(privateKeyParams.DP)}\nDQ: {Convert.ToBase64String(privateKeyParams.DQ)}\nInverseQ: {Convert.ToBase64String(privateKeyParams.InverseQ)}";
}


using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using StokMuhasebe.Application.Kimlik;

namespace StokMuhasebe.Api;

internal static class JwtUretici
{
    /// <summary>Token'a firma, kullanıcı, rol ve yetki bilgisi konur; imza anahtarı yapılandırmadan gelir.</summary>
    public static (string Token, DateTime Bitis) Uret(KimlikSonucu kimlik, string firmaKodu, string anahtar, TimeSpan omur)
    {
        var claimler = new List<Claim>
        {
            new("firma", firmaKodu),
            new("kullanici_id", kimlik.KullaniciId.ToString()),
            new("ad", kimlik.AdSoyad),
            new("rol", kimlik.Rol)
        };
        claimler.AddRange(kimlik.Yetkiler.Select(y => new Claim("yetki", y)));

        var bitis = DateTime.UtcNow.Add(omur);
        var token = new JwtSecurityToken(
            claims: claimler,
            expires: bitis,
            signingCredentials: new SigningCredentials(
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(anahtar)), SecurityAlgorithms.HmacSha256));

        return (new JwtSecurityTokenHandler().WriteToken(token), bitis);
    }
}

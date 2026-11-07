using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Data.SqlClient;
using Microsoft.IdentityModel.Tokens;
using StokMuhasebe.Api;
using StokMuhasebe.Application;
using StokMuhasebe.Application.Faturalar;
using StokMuhasebe.Application.Kimlik;
using StokMuhasebe.Application.Referans;
using StokMuhasebe.Application.Tahsilat;
using StokMuhasebe.Infrastructure;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddInfrastructure();

// İmza anahtarı koda/appsettings'e YAZILMAZ: user-secrets, ortam değişkeni veya secret store'dan gelir.
var jwtAnahtar = builder.Configuration["Jwt:Anahtar"]
    ?? throw new InvalidOperationException("Jwt:Anahtar tanımlı değil (en az 32 karakter; user-secrets ile ayarlayın).");

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(o => o.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = false,
        ValidateAudience = false,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtAnahtar))
    });

// Her yetki kodu için bir politika: token'da "yetki" claim'i olmalı.
builder.Services.AddAuthorization(o =>
{
    foreach (var yetki in Yetkiler.Hepsi)
        o.AddPolicy(yetki, p => p.RequireClaim("yetki", yetki));
});

var app = builder.Build();

// İş kuralı ve veritabanı kuralı (THROW 50000-50099) hatalarını 422 olarak, mesajıyla döndür.
// Diğer hatalar 500 olarak kalır, ayrıntı dışarı sızdırılmaz.
app.Use(async (ctx, next) =>
{
    try { await next(); }
    catch (IsKuraliHatasi e)
    {
        ctx.Response.StatusCode = StatusCodes.Status422UnprocessableEntity;
        await ctx.Response.WriteAsJsonAsync(new { hata = e.Message });
    }
    catch (SqlException e) when (e.Number is >= 50000 and < 50100)
    {
        ctx.Response.StatusCode = StatusCodes.Status422UnprocessableEntity;
        await ctx.Response.WriteAsJsonAsync(new { hata = e.Message });
    }
});

app.UseAuthentication();
app.UseAuthorization();

static (string Firma, int KullaniciId) Oturum(ClaimsPrincipal k)
{
    var firma = k.FindFirstValue("firma") ?? throw new IsKuraliHatasi("Oturumda firma bilgisi yok.");
    return (firma, int.TryParse(k.FindFirstValue("kullanici_id"), out var id) ? id : 0);
}

// ---------------- Giriş ----------------
// Not: IP bazlı hız sınırlama (rate limiting) henüz yok; hesap bazlı kilit (5 hata / 15 dk) KimlikServisi'nde.
app.MapPost("/api/giris", async (GirisIstegi istek, IKimlikServisi kimlik, CancellationToken ct) =>
    {
        var sonuc = await kimlik.DogrulaAsync(istek.FirmaKodu, istek.KullaniciAdi, istek.Sifre, ct);
        var firmaKodu = istek.FirmaKodu.Trim();
        var (token, bitis) = JwtUretici.Uret(sonuc, firmaKodu, jwtAnahtar, TimeSpan.FromHours(8));
        return Results.Ok(new GirisYaniti(token, bitis, sonuc.KullaniciId, sonuc.AdSoyad, sonuc.Rol, firmaKodu, sonuc.Yetkiler));
    })
    .AllowAnonymous();

// ---------------- Referans (açılır listeler) ----------------
app.MapGet("/api/referans/cariler", async (ClaimsPrincipal kullanici, IReferansServisi servis, CancellationToken ct) =>
    {
        var (firma, _) = Oturum(kullanici);
        return Results.Ok(await servis.SatisCarileriniListeleAsync(firma, ct));
    })
    .RequireAuthorization(Yetkiler.FaturaGor);

app.MapGet("/api/referans/stoklar", async (ClaimsPrincipal kullanici, IReferansServisi servis, CancellationToken ct) =>
    {
        var (firma, _) = Oturum(kullanici);
        return Results.Ok(await servis.StoklariListeleAsync(firma, ct));
    })
    .RequireAuthorization(Yetkiler.FaturaGor);

// ---------------- Satış faturası ----------------
app.MapPost("/api/faturalar/satis", async (
        FaturaOlusturIstegi istek, ClaimsPrincipal kullanici, IFaturaServisi servis, CancellationToken ct) =>
    {
        var (firma, kullaniciId) = Oturum(kullanici);
        var sonuc = await servis.SatisFaturasiKesAsync(firma, kullaniciId, istek, ct);
        return Results.Created($"/api/faturalar/{sonuc.FaturaId}", sonuc);
    })
    .RequireAuthorization(Yetkiler.FaturaKes);

// Taslak: istek.TaslakId boşsa yeni taslak, doluysa o taslak güncellenir.
app.MapPost("/api/faturalar/satis/taslak", async (
        FaturaOlusturIstegi istek, ClaimsPrincipal kullanici, IFaturaServisi servis, CancellationToken ct) =>
    {
        var (firma, kullaniciId) = Oturum(kullanici);
        return Results.Ok(await servis.TaslakKaydetAsync(firma, kullaniciId, istek, ct));
    })
    .RequireAuthorization(Yetkiler.FaturaKes);

app.MapGet("/api/faturalar/satis/taslak", async (ClaimsPrincipal kullanici, IFaturaServisi servis, CancellationToken ct) =>
    {
        var (firma, _) = Oturum(kullanici);
        return Results.Ok(await servis.TaslaklariListeleAsync(firma, ct));
    })
    .RequireAuthorization(Yetkiler.FaturaGor);

app.MapDelete("/api/faturalar/satis/taslak/{id:int}", async (
        int id, ClaimsPrincipal kullanici, IFaturaServisi servis, CancellationToken ct) =>
    {
        var (firma, kullaniciId) = Oturum(kullanici);
        await servis.TaslakSilAsync(firma, kullaniciId, id, ct);
        return Results.NoContent();
    })
    .RequireAuthorization(Yetkiler.FaturaKes);

app.MapGet("/api/faturalar/{id:int}", async (
        int id, ClaimsPrincipal kullanici, IFaturaServisi servis, CancellationToken ct) =>
    {
        var (firma, _) = Oturum(kullanici);
        var detay = await servis.DetayGetirAsync(firma, id, ct);
        return detay is null ? Results.NotFound() : Results.Ok(detay);
    })
    .RequireAuthorization(Yetkiler.FaturaGor);

// ---------------- Alış faturası ----------------
app.MapPost("/api/faturalar/alis", async (
        AlisFaturaOlusturIstegi istek, ClaimsPrincipal kullanici, IFaturaServisi servis, CancellationToken ct) =>
    {
        var (firma, kullaniciId) = Oturum(kullanici);
        var sonuc = await servis.AlisFaturasiKaydetAsync(firma, kullaniciId, istek, ct);
        return Results.Created($"/api/faturalar/{sonuc.FaturaId}", sonuc);
    })
    .RequireAuthorization(Yetkiler.FaturaAlisGir);

// ---------------- Tahsilat / ödeme ----------------
app.MapPost("/api/tahsilat-odeme", async (
        TahsilatOdemeIstegi istek, ClaimsPrincipal kullanici, ITahsilatOdemeServisi servis, CancellationToken ct) =>
    {
        var (firma, kullaniciId) = Oturum(kullanici);
        var sonuc = await servis.KaydetAsync(firma, kullaniciId, istek, ct);
        return Results.Created($"/api/tahsilat-odeme/{sonuc.TahsilatOdemeId}", sonuc);
    })
    .RequireAuthorization(Yetkiler.FinansTahsilatOdeme);

// YALNIZCA GELİŞTİRME: Production'da asla yayınlanmaz (IsDevelopment kontrolü).
if (app.Environment.IsDevelopment())
{
    // Giriş olmadan test token'ı (tüm yetkilerle).
    app.MapGet("/dev/token", (string firma, int kullanici) =>
    {
        var kimlik = new KimlikSonucu(kullanici, "Geliştirme kullanıcısı", "Yonetici", Yetkiler.Hepsi);
        var (token, _) = JwtUretici.Uret(kimlik, firma, jwtAnahtar, TimeSpan.FromHours(8));
        return Results.Ok(new { token });
    });

    // Şifre hash'i üretir; çıktıyı Kullanici.SifreHash alanına yazın. Gerçek şifrelerle KULLANMAYIN
    // (adres günlüklere yazılabilir); yalnızca deneme şifreleri için.
    app.MapGet("/dev/sifre-hash", (string sifre) => Results.Text(SifreHasher.Hash(sifre)));
}

app.Run();

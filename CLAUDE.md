# CLAUDE.md

> Proje adı henüz belirlenmedi. `<PROJE>` yazan yerleri repo adıyla değiştir.

## Proje

`<PROJE>` — bir domain veya IP alıp o hedefin dışarıdan görünen güvenlik durumunu
tek raporda çıkaran açık kaynak tarayıcı. MIT lisanslı.

Girdi: tek domain veya IP. Çıktı: tek seferlik, durum saklamayan bir rapor.

## v1 KAPSAMI (bunun dışına ÇIKMA)

1. HTTP durum kodu + redirect zinciri (son hedef dahil)
2. SSL/TLS: geçerlilik, bitiş tarihi, issuer, zincir hatası
3. Güvenlik header'ları: HSTS, CSP, X-Frame-Options, X-Content-Type-Options,
   Referrer-Policy, Permissions-Policy
4. Teknoloji + versiyon tespiti (pasif: header + HTML imzaları)
5. Tespit edilen ürün/versiyonlar için CVE eşleştirme (NVD API, runtime + cache)
6. `--json` çıktısı

## v1'DE OLMAYACAKLAR

Bunlardan biri istenirse **yapma, önce sor**:
kullanıcı hesabı · veritabanı · ödeme/Stripe · reklam · mail gönderimi ·
PDF rapor · toplu/çoklu domain tarama · zamanlanmış tarama · Docker ·
CI/CD · analytics · i18n altyapısı

Sebep: v1 bir haftada bitmeli. Kapsam büyümesi bu projeyi öldürür.

## Mimari

```
/core     tarama motoru — saf, yan etkisiz, DB yok, HTTP dışında I/O yok
          scan(target, opts) -> ScanResult
/cli      npx ile çalışan komut satırı; core'u çağırır
/web      Next.js App Router; core'u çağırır; tek domain formu
```

**Kural:** iş mantığı SADECE `core`'da. `cli` ve `web` ince kabuktur, mantık
içermez. Kurumsal çok-domain sürümü ileride `core`'a dokunmadan eklenecek —
bu yüzden `core` hiçbir zaman DB, session, kullanıcı kavramı bilmez.

## Stack

TypeScript (strict) · Node 20+ · `undici` (HTTP) · `tls` (yerleşik modül) ·
Next.js App Router (web) · `vitest` (test)

Yeni bağımlılık eklemeden önce sor. Postinstall script'i indirme yapan
paketleri (puppeteer vb.) ASLA ekleme.

## Kırmızı çizgiler

**PASİF TARAMA.** Sadece normal bir tarayıcının yapacağı istekler yapılır:
hedefin sayfasını çek, header'ları oku, TLS el sıkışması yap. Şunlar YASAK:
port tarama · dizin/subdomain brute force · exploit denemesi · form gönderme ·
kimlik doğrulama denemesi · saniyede 5'ten fazla istek.

Sebep: kullanıcı sahibi olmadığı hedefi tarayabilir. Aktif tarama hem yasal
risk hem de sunucumuzun karalisteye girmesi demektir.

**CVE eşleştirmesi yanılabilir.** Debian/RHEL paketleri güvenlik yamalarını
backport eder; banner "nginx 1.18" der ama açık kapalı olabilir. Her CVE
bulgusu raporda "banner versiyonuna dayalı, doğrulanmamış" ibaresiyle
çıkmalı. Kesinlik iddia eden metin yazma.

**Zaman aşımı ≠ sunucu hatası.** Yavaş ama sağlıklı site 5xx olarak
işaretlenmemeli. `ECONNABORTED / ETIMEDOUT / ENOTFOUND / ECONNRESET`
ayrı bir `TIMEOUT` / `UNREACHABLE` durumuna gider. Timeout 30sn.

## Kod kuralları

- Tanımlayıcılar, dosya adları, commit mesajları, README: **İngilizce**
  (repo halka açık olacak). Sohbet Türkçe, kod İngilizce.
- `any` yok. Tüm dış veri (HTTP yanıtı, NVD cevabı) tipli parse edilir.
- Her `core` fonksiyonu için vitest testi. Ağ çağrıları test'te mock'lanır.
- Hata yutma yok: boş `catch {}` yasak, her hata ya işlenir ya yukarı atılır.

## Çalışma şekli

- Değişikliğe başlamadan önce **plan sun, onay bekle**.
- Tek seferde tek konu. "Bu arada şunu da düzelttim" yapma.
- Bir dosyayı değiştirdiysen ilgili testi de çalıştır ve sonucu göster.
- Bir v1 adımı bitip testleri geçince, aynı iş içinde bu dosyadaki
  **"Şu an nerede"** bölümünü de güncelle.
- Commit'i ben atacağım; sen `git commit`/`git push` çalıştırma.

## Şu an nerede

Monorepo iskeleti kuruldu (`core` + `cli` workspace'leri, TypeScript strict, vitest).
v1 kapsam maddelerine göre durum:

- ✅ **(1) HTTP + redirect zinciri** — `core/src/scan.ts`. Durum kodu, redirect
  zinciri, son gövdenin okunması (512 KB cap, UTF-8 sınırında kesme).
  Test: `core/test/scan.test.ts`
- ✅ **(2) SSL/TLS** — `core/src/ssl.ts` (`checkSsl`). Test: `core/test/ssl.test.ts`
- ✅ **(3) Güvenlik header'ları** — `core/src/headers.ts` (`checkHeaders`), altı
  header. Test: `core/test/headers.test.ts`
- ✅ **(4) Teknoloji tespiti** — `core/src/tech.ts` (`detectTech`) +
  `core/src/signatures.ts` (22 pasif imza, veri-only). Eşleşme kaynakları: header /
  cookie / HTML / meta generator / script src; confidence hangi kaynağın eşleştiğinden
  türetiliyor (header & meta generator = high, cookie & HTML = medium,
  script src = low). `scan()` ek istek atmadan eldeki yanıtı kullanıyor.
  Test: `core/test/tech.test.ts`
- ⬜ **(5) CVE eşleştirme** — başlanmadı. NVD API, runtime + cache. Her bulgu
  "banner versiyonuna dayalı, doğrulanmamış" ibaresiyle çıkacak. Eşleştirme için
  `TechResult.vendor` / `.product` (CPE) alanları hazır.
- ⬜ **(6) `--json` çıktısı** — başlanmadı. `cli/src/index.ts` hâlâ boş placeholder;
  argüman ayrıştırma yok.

`ScanResult` (bkz. `core/src/types.ts`) şu an `http` / `ssl` / `headers` / `tech`
alanlarını dolduruyor; sadece `cves` boş dizi.

`web/` henüz boş (`.gitkeep`). Proje adı belirlenmedi — bu dosyadaki `<PROJE>`
placeholder'ı repo adıyla değiştirilecek.

Sıradaki hedef: (5) CVE eşleştirme adımı.
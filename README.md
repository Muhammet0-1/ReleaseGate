# Release Gate

Release Gate, imzalı OCI imajından trafiği alan Docker konteynerine kadar aynı sürümün izlendiğini denetleyen bir yerel sürüm kabul kapısıdır. `parcel-note` adlı sentetik servisle terfi, güncel politikaya göre geri dönüş ve veri sürekliliği prova edilir.

Faz 3’ün 23 Kasım 2026 UTC tarihli yerel Docker provasında **5/5 senaryo** ve **11 konteyner** kaydedildi. Geliştirme koşusunda ayrıca **78/78 regresyon testi** geçti. Docker provası ayrı bir koşuydu. [Faz 3 seçili kanıtları](docs/evidence/phase3-summary.json)

## Provada ne görüldü?

| Vaka | Gözlem | Son seçim | Çıkış |
| --- | --- | --- | ---: |
| Sağlıklı aday | Aday `200` verdi ve iki sentetik kaydı okudu. Ortak adres yeni örnekten aynı kayıtları sundu. | Yeşil | `0` |
| Aday `503` | Önceki mavi örnek güncel politikadan onay aldı. Özel API ve ortak adres iki kaydı da okudu. | Aynı mavi | `2` |
| Geri dönüş onayı çekildi | Aday `503`, mavi digest’i politika dışı. Ortak adres `503`, iki kayıt mavi özel API’de okunabildi. | Trafik bekletildi | `3` |
| Yanlış örnekten `200` | Aynı imajı kullanan ikinci örneğin tam konteyner kimliği farklıydı. `WRONG_CONTAINER`. | Aynı mavi | `2` |
| Manifest ve çalışan imaj uyuşmadı | Engine’in gördüğü imaj ile iddia edilen imaj farklıydı. `CONTAINER_IMAGE_MISMATCH`. | Aynı mavi | `2` |

`2` kodlu vakalarda aday reddedildi. CLI bunu `rolled_back` olarak kaydetti. Prova boyunca başlangıçtaki mavi konteyner yerinde kaldı, trafik önce yeşile taşınmadı. `3`, güncel geri dönüş onayı bulunmadığı için operatör kararı gerektiren durumu gösterir. Beş vakanın sonunda görev etiketli konteyner, volume ve yükleme etiketi kalmadığı bağımsız gözlem kayıtlarında görüldü.

## Karar zinciri

1. **Sürüm kararı.** Tam `repository@sha256:…` referansındaki manifest ve işaret ettiği OCI config ve katman denetlenir. Sigstore, manifest imzasını ve imzalı köken beyanını ayrı sabit açık anahtarlarla doğrular. Operatör politikası onaylı digest, depo, commit, workflow, builder ve test ortamını ayrıca karşılaştırır.
2. **Çalışan imaj bağı.** İmzalı manifestin gösterdiği config özeti, Docker’dan dışa verilen config baytlarıyla karşılaştırılır. Bu Engine’de gözlenen imaj kimliği manifest digest’i biçimindeydi. Bu nedenle imaj arşivinin tek manifest hedefi, config bağı ve konteynerin manifest tanımlayıcısı da eşleştirildi. Manifest digest’i, config digest’i ve tam konteyner ID’si ayrı alanlardır.
3. **Sağlık, veri ve rota.** Denetleyici adayın özel Unix HTTP endpoint’ini o tam konteyner kimliğinde kontrol eder. Terfi öncesi iki sentetik kaydı okur. Aday reddedilirse önceki örneğin imzaları, güncel geri dönüş politikası, kimliği, sağlığı ve verisi yeniden denetlenir. Rota ortak Unix HTTP adresinde tam konteyner kimliğine göre seçilir.

## Bu deponun kapsamı

Bu kopyada doğrulayıcı, Docker denetleyicisi, sentetik test kaynakları ve kayıttan seçilmiş kanıt özeti bulunur. Hazır OCI blob’ları, test korpusu, imzalı fixture’lar ve ham koşu günlükleri ayrı tutulur. Bu yüzden bu depoyu tek başına klonlamak, regresyon paketini veya Docker provasını çalıştırmak için yeterli değildir. Kaydedilmiş sonuçlar, gerekli fixture’ları içeren ayrı geliştirme ortamına aittir.

Geliştirme ortamında Node.js, `@sigstore/verify` 4.1.0 ve `@sigstore/bundle` 5.0.0 kullanıldı. Fixture üretimi ayrıca `@sigstore/sign` 5.0.0 ve yerel derleme araçları gerektirir. Docker provası Linux Engine, Python 3, tar ve özel çalışma dizininde Unix soketi ister. Kaydedilmiş kurulum Linux `amd64`, Docker Engine `29.10.0` ve containerd imaj deposudur. Denetleyici içindeki `prepare` ve `preflight` adımları sırasıyla kanıt bağını ve yerel Engine önkoşullarını kontrol eder.

## Test verisi ve güven sınırı

Fixture’daki iki imza rolü P-256 eğitim anahtarlarıyla ayrılmıştır. Test politikalarındaki P-256 anahtarları **açık doğrulama anahtarlarıdır**. Test üreticisindeki geçici özel anahtar bellekte kullanılır. Paylaşım listesine özel anahtar malzemesi girmez. Depo, workflow ve commit referansları sentetiktir. İmzalar gerçek kriptografik doğrulayıcıdan geçer. Bu sabit anahtar profili bir üretim CI geçmişi, Fulcio/OIDC kimliği veya Rekor kaydı kanıtlamaz.

Prova tek makine, tek platform ve sentetik veri kapsamındadır. Mavi ve yeşil aynı koşunun volume’ünü kullandı. İki kaydın tekrar okunması bu veri sürekliliğini gösterir. Üretim, Kubernetes, canlı registry, dağıtık trafik ve yedekten dönüş bu provanın kapsamı dışındadır.

Bu kaynak kopyası için bir açık kaynak lisansı seçilmedi.

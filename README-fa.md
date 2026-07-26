<div align="center">

<img src="https://em-content.zobj.net/source/microsoft-teams/363/high-voltage_26a1.png" width="88" alt="IranX Panel" />

# IranX Panel

### پنل اشتراک VLESS، تک‌فایلی و قابل اجرا روی هر جایی

مدیریت کاربر، حجم و لینک اشتراک — همه در یک فایل پایتون.
دو ترنسپورت، شش تم، دوزبانه — بدون Xray core، بدون Docker، بدون VPS.

<p>
  <img src="https://img.shields.io/badge/Python-3.9%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI" />
  <img src="https://img.shields.io/badge/SQLite-003B57?style=for-the-badge&logo=sqlite&logoColor=white" alt="SQLite" />
  <img src="https://img.shields.io/badge/License-MIT-22c55e?style=for-the-badge" alt="MIT" />
</p>

<p>
  <img src="https://img.shields.io/badge/Railway-ready-0B0D0E?style=flat-square&logo=railway&logoColor=white" alt="Railway" />
  <img src="https://img.shields.io/badge/Render-ready-46E3B7?style=flat-square&logo=render&logoColor=black" alt="Render" />
  <img src="https://img.shields.io/badge/VLESS-WS%20%2B%20TLS-6366f1?style=flat-square" alt="WS+TLS" />
  <img src="https://img.shields.io/badge/VLESS-XHTTP%20%2B%20TLS-d946ef?style=flat-square" alt="XHTTP+TLS" />
</p>

[English](README.md) · **فارسی**

</div>

---

## چرا این پنل

بیشتر پنل‌ها VPS، دامنه، گواهی TLS و باینری Xray می‌خواهند. این یکی فقط یک حساب رایگان
PaaS می‌خواهد. TLS را خودِ پلتفرم انجام می‌دهد، پس `main.py` هر دو inbound را با پایتون
خالص پیاده کرده و TCP را رله می‌کند — چیزی نصب نمی‌کنی، چیزی هم تمدید نمی‌کنی.

```
┌──────────┐   wss:// یا https://   ┌─────────────┐   TCP   ┌────────────┐
│  کلاینت  │ ─────────────────────▶ │ IranX Panel │ ──────▶ │   مقصد     │
└──────────┘   TLS در PaaS تمام می‌شود └─────────────┘        └────────────┘
```

---

## قابلیت‌ها

<table>
<tr>
<td width="50%" valign="top">

**دسترسی و امنیت**
- ورود فقط با رمز — یوزرنیم همیشه `admin`
- رمز را خودت در **اولین ورود** تعیین می‌کنی
- هش PBKDF2-SHA256 با ۲۰۰٬۰۰۰ دور
- محدودیت تلاش ورود، کوکی JWT
- لاگ رخداد: ورود، اتصال رد شده، تغییر UUID

</td>
<td width="50%" valign="top">

**کاربران**
- ساخت، ویرایش، فعال/غیرفعال، حذف
- حجم گیگابایتی برای هر کاربر (`۰` = بی‌نهایت)
- انقضا بر حسب روز
- محدودیت دستگاه از **IP یکتای فعال**
- تغییر UUID برای قطع کانفیگ لو رفته

</td>
</tr>
<tr>
<td valign="top">

**ترنسپورت‌ها**
- `VLESS + WS + TLS`
- `VLESS + XHTTP + TLS` *(packet-up)*
- انتخابی برای هر کاربر: یکی، دیگری، یا هر دو
- ترنسپورت اشتباه برای کاربر رد می‌شود

</td>
<td valign="top">

**رابط کاربری**
- منوی همبرگری با پنج بخش
- شش تم، ذخیره‌شده در مرورگر
- دوزبانه فارسی/انگلیسی، سازگار با RTL
- نمودار ۲۴ ساعت، تفکیک ترنسپورت
- QR Code برای هر لینک اشتراک

</td>
</tr>
</table>

---

## شروع سریع

<details open>
<summary><b>نصب روی Railway</b></summary>

<br>

**۱.** این ریپو را فورک کن، یا فایل‌ها را در ریپوی خودت آپلود کن.

**۲.** [railway.app](https://railway.app) → **New Project** → **Deploy from GitHub repo** → انتخابش کن.

**۳.** تب **Variables** را باز کن:

| متغیر | نمونه | |
|---|---|---|
| `SECRET_KEY` | یک رشته تصادفی بلند | **لازم** |
| `DOMAIN` | `myapp.up.railway.app` | **لازم** |
| `WS_PATH` | `ws` | اختیاری |
| `XHTTP_PATH` | `xh` | اختیاری |
| `DEVICE_WINDOW` | `300` | اختیاری |
| `SESSION_IDLE` | `90` | اختیاری |
| `DB_PATH` | `/tmp/panel.db` | اختیاری |
| `ADMIN_PASSWORD` | — | اختیاری، صفحه Setup را رد می‌کند |

**۴.** **Settings → Networking → Generate Domain** — همان مقدار را در `DOMAIN` بگذار و Redeploy کن.

**۵.** برو `https://دامنه‌ات/` — صفحه Setup می‌آید. رمز بگذار. تمام.

> [!TIP]
> روی پلن Trial ممکن است اولین build تا ده دقیقه در `QUEUED` بماند و حتی شروع نشود.
> این طبیعی است — قبل از اینکه فکر کنی چیزی خراب شده، صبر کن.

</details>

<details>
<summary><b>نصب روی Render</b></summary>

<br>

Render خودش `render.yaml` را می‌خواند. یک **Web Service** بساز، ریپو را وصل کن،
و `SECRET_KEY` و `DOMAIN` را در بخش Environment اضافه کن.

</details>

<details>
<summary><b>هر هاست ASGI دیگر</b></summary>

<br>

```bash
pip install -r requirements.txt
gunicorn -k uvicorn.workers.UvicornWorker main:app --bind 0.0.0.0:$PORT --timeout 0
```

هر جایی که TLS را تمام کند و WebSocket upgrade را فوروارد کند کار می‌کند.

</details>

---

## بخش‌های پنل

| بخش | محتوا |
|:--|:--|
| **داشبورد** | آمار کلی، نمودار ۲۴ ساعت، تفکیک WS/XHTTP، تعداد سشن زنده XHTTP |
| **مدیریت کاربران** | ساخت، لیست، ویرایش، کانفیگ و لیست IP هر کاربر |
| **Clean IP** | افزودن تکی و انبوه، فعال/غیرفعال، حذف |
| **تنظیمات پنل** | تم، زبان، تغییر رمز، اطلاعات سرور |
| **رخدادها** | تلاش‌های ورود، اتصال‌های رد شده، تغییر UUID |

---

## ترنسپورت‌ها

هر کاربر روی یکی از این سه حالت تنظیم می‌شود:

| حالت | چه چیزی در لینک اشتراکش می‌آید |
|:--|:--|
| `WS + TLS` | فقط کانفیگ‌های `type=ws` |
| `XHTTP + TLS` | فقط کانفیگ‌های `type=xhttp` با `mode=packet-up` |
| **هر دو** | هر دو نوع، و برای هر Clean IP یکی از هر کدام |

```
WebSocket   wss://<domain>/<WS_PATH>          پیش‌فرض /ws
XHTTP       https://<domain>/<XHTTP_PATH>/…   پیش‌فرض /xh
```

این دو مسیر باید با هم متفاوت باشند.

> [!WARNING]
> **XHTTP آزمایشی است.** به شکل `packet-up` پیاده شده: درخواست‌های `POST` شماره‌دار برای
> uplink، یک `GET` استریمی برای downlink، به همراه بافر مرتب‌سازی برای چانک‌های نامرتب.
> اگر پروکسی یا CDN ای در مسیر پاسخ را بافر کند، downlink می‌ماند.
> **WS مسیر پایدار است** — اگر کاربری به مشکل خورد، روی WS بگذارش.

---

## Clean IP

آدرس‌های تمیز را یک بار اضافه کن؛ به لینک اشتراک **همه** کاربران به عنوان کانفیگ اضافی
اضافه می‌شوند. آدرس اتصال همان Clean IP می‌شود ولی `sni` و `host` روی دامنه اصلی می‌ماند.

ورودی انبوه، هر خط یک مورد و برچسب بعد از `#`:

```
104.16.132.229  # ایرانسل
172.67.72.14    # همراه اول
cdn.example.com # پشتیبان
188.114.97.3
```

با ⏸ می‌توانی یک آدرس را بدون حذف غیرفعال کنی.

---

## خروجی لینک اشتراک

مورد اول یک **کانفیگ اطلاعات** است — پوچ و غیرقابل اتصال، فقط برای اینکه کلاینت وضعیت
حساب را بالای لیست نشان بدهد:

```
📊 ali_home | 20.50GB | 22Days
🌐 ali_home · WS · Default
⚡ ali_home · Irancell · WS
🌐 ali_home · XHTTP · Default
⚡ ali_home · Irancell · XHTTP
```

روی پورت ۸۰ با `security=none` و مسیری است که هیچ‌کدام از inbound ها به آن گوش نمی‌دهند،
پس هیچ‌وقت وصل نمی‌شود. هدر `subscription-userinfo` هم ست می‌شود تا Hiddify و Streisand
حجم و انقضا را در رابط خودشان هم نشان بدهند.

---

## قطع کانفیگ لو رفته

**مدیریت کاربران → ویرایش:**

- **UUID جدید** — یک UUID تصادفی نو، و لیست IP ها پاک می‌شود
- **UUID دستی** — هر UUID دلخواه

کانفیگ‌های قدیمی بلافاصله از کار می‌افتند. لینک اشتراک عوض نمی‌شود، پس کاربر فقط
باید Subscription خودش را Update کند.

---

## محدودیت دستگاه چطور کار می‌کند

هر IP مبدأ همراه با پروتکلش ثبت می‌شود و تا `DEVICE_WINDOW` ثانیه پس از آخرین اتصال
«دستگاه فعال» شمرده می‌شود. وقتی سقف پر شود، IP جدید رد می‌شود. دکمه **IP ها** لیست
دقیق را با وضعیت آنلاین و پروتکل هر دستگاه نشان می‌دهد.

> [!NOTE]
> چند دستگاه پشت یک روتر خانگی یک IP مشترک دارند و یک دستگاه شمرده می‌شوند.
> این ذاتِ روش IP-based است، باگ نیست.

---

## ساختار پروژه

```
main.py             هسته — FastAPI، هر دو inbound، رابط کاربری امبد شده
requirements.txt    وابستگی‌های قفل‌شده
Procfile            دستور اجرا برای Railway / Render / Heroku
railway.json        تنظیمات دیپلوی Railway
render.yaml         تنظیمات دیپلوی Render
panel-config.toml   مرجع متغیرهای محیطی
```

---

## چیزهایی که خوب است بدانی

- **دیتابیس روی `/tmp` موقت است** و با هر ریدیپلوی پاک می‌شود. برای دائمی شدن، یک Volume
  وصل کن و `DB_PATH=/data/panel.db` بگذار.
- **UDP پشتیبانی نمی‌شود** — فقط TCP. در کلاینت DNS را روی DoH بگذار.
- ارتقا از نسخه قدیمی‌تر بی‌خطر است: ستون‌های جدید خودکار با `ALTER TABLE` اضافه می‌شوند.
- پهنای باند مصرفی کاربرها را ارائه‌دهنده هاست از تو حساب می‌کند. حواست به صورت‌حساب باشد.
- برای استفاده شخصی و آموزشی ساخته شده.

---

<div align="center">

**MIT** · issue و pull request پذیرفته می‌شود

</div>

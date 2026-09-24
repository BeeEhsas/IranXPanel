<div align="center">

# IranX Panel

### نصب دستی روی Cloudflare Workers + D1

[![Cloudflare Workers](https://img.shields.io/badge/Cloudflare-Workers-F38020?style=flat-square&logo=cloudflare&logoColor=white)](#)
[![D1 Database](https://img.shields.io/badge/D1-Database-005DAA?style=flat-square&logo=cloudflare&logoColor=white)](#)
[![VLESS WebSocket](https://img.shields.io/badge/VLESS-WebSocket-7C5CFF?style=flat-square&logo=protonmail&logoColor=white)](#)

**فارسی:** [راهنمای فارسی](README-fa.md) · **English:** [English guide](README.md)

</div>

---

<div dir="rtl" align="right">

## معرفی کوتاه

پنل مدیریت IranX را مستقیماً از داخل **Cloudflare Dashboard** نصب کنید. این مخزن عمومی فقط شامل Worker آماده، ساختار D1 و راهنمای نصب است؛ سورس خصوصی Auto‑Deployer هیچ‌کدام از فایل‌های آن در این مخزن قرار ندارد.

### چه چیزهایی لازم دارید؟

- حساب Cloudflare
- حدود پنج دقیقه برای نصب
- سه فایل عمومی موجود در همین مخزن

### کاربر چه چیزی را تنظیم می‌کند؟

کاربر فقط این سه کار را انجام می‌دهد:

1. Worker و دیتابیس D1 را می‌سازد.
2. دیتابیس را به Worker متصل می‌کند.
3. پنل را باز می‌کند و رمز مدیر را خودش انتخاب می‌کند.

پنل خودش کلید نشست را می‌سازد، دامنهٔ عمومی `workers.dev` را از آدرس درخواست تشخیص می‌دهد و مسیرهای پیش‌فرض را اعمال می‌کند. دیگر نیازی به ثبت دستی `SECRET_KEY`، `DOMAIN`، `RELAY_DOMAIN` یا سایر متغیرها نیست.

---

## راهنمای نصب

### مرحلهٔ ۱ — ساخت Worker

1. وارد [Cloudflare Dashboard](https://dash.cloudflare.com/) شوید.
2. به مسیر **Workers & Pages** بروید.
3. یک Worker با نام کوتاهی مثل `iranx-panel` بسازید.
4. وارد **Edit code** شوید و کد پیش‌فرض را با کل محتوای فایل [`index.js`](index.js) جای‌گذاری کنید.
5. از مسیر **Settings → Runtime → Compatibility flags** گزینهٔ زیر را فعال کنید:

```text
nodejs_compat
```

> فعال‌کردن `nodejs_compat` ضروری است و نباید رد شود.

### مرحلهٔ ۲ — ساخت دیتابیس D1

1. در Cloudflare Dashboard وارد **Storage & Databases → D1 SQL Database** شوید.
2. یک دیتابیس با نامی مثل `iranx-panel-db` بسازید.
3. وارد **Console** دیتابیس شوید.
4. فایل [`schema.sql`](schema.sql) را کامل باز کنید، تمام محتوای آن را در D1 Console paste کنید و اجرا بگیرید.
5. مطمئن شوید جدول‌های پنل ساخته شده‌اند، سپس ادامه دهید.

### مرحلهٔ ۳ — اتصال D1 به Worker

به مسیر زیر برگردید:

```text
Settings → Bindings → Add → D1 Database
```

تنظیمات را این‌طور وارد کنید:

| فیلد | مقدار |
|---|---|
| Variable name | `DB` |
| D1 database | دیتابیسی که در مرحلهٔ ۲ ساختید |

> نام binding باید **دقیقاً `DB`** باشد.

### مرحلهٔ ۴ — انتشار و تعیین رمز

1. روی **Deploy** بزنید.
2. آدرس نهایی `https://<worker>.<account>.workers.dev` را باز کنید.
3. رمز مدیر را دو بار وارد کنید.
4. رمز باید حداقل ۸ کاراکتر و شامل این موارد باشد: یک حرف بزرگ انگلیسی، یک حرف کوچک انگلیسی و یک رقم.

نام کاربری مدیر همیشه این است:

```text
admin
```

رمز با الگوریتم PBKDF2-SHA256 هش می‌شود و داخل D1 نگهداری می‌شود؛ هیچ رمزی داخل ریپوی عمومی قرار نمی‌گیرد.

---

## بررسی نصب

بعد از راه‌اندازی، موارد زیر را بررسی کنید:

- آدرس `/healthz` مقدار `{"ok":true,"platform":"cloudflare"}` را برگرداند.
- صفحهٔ `/setup` فقط پیش از تعیین رمز قابل دسترسی باشد.
- مدیر بتواند کاربر بسازد و لینک سابسکریپشن دریافت کند.
- مسیر WebSocket با آدرس `/ws` در دسترس باشد.
- لینک‌های سابسکریپشن به‌صورت خودکار از دامنهٔ عمومی Worker ساخته شوند.

برای بررسی مستقیم Health Check این آدرس را باز کنید:

```text
https://<worker>.<account>.workers.dev/healthz
```

---

## چک‌لیست امنیتی

- هرگز API Token، شناسهٔ حساب، رمز عبور یا Secret را commit نکنید.
- برای پنل مدیر یک رمز یکتا و قدرتمند انتخاب کنید.
- binding دیتابیس D1 را به Workerهای نامرتبط وصل نکنید.
- اگر اطلاعات محرمانه‌ای داخل commit یا لاگ عمومی رفته است، آن را فوراً حذف و باطل کنید.
- پیش از اضافه‌کردن کاربران زیاد، محدودیت‌های حساب Cloudflare را بررسی کنید.

---

## نکات مهم

- Workers Free محدودیت تعداد درخواست و اتصال هم‌زمان دارد.
- آدرس `workers.dev` ممکن است در بعضی شبکه‌ها، از جمله برخی شبکه‌های داخل ایران، مسدود باشد.
- ترانسپورت عملیاتی نسخهٔ Cloudflare، **VLESS روی WebSocket** است.
- XHTTP در مدل پنل وجود دارد، اما پیاده‌سازی آن هنوز برای استفادهٔ production کامل نشده است.
- استفاده از Cloudflare Workers تابع شرایط Cloudflare و قوانین محل است.

---

## فایل‌های این مخزن

```text
.
├── index.js       # فایل آمادهٔ Cloudflare Worker
├── schema.sql     # ساختار دیتابیس D1
├── README.md      # راهنمای انگلیسی
└── README-fa.md   # همین راهنمای فارسی
```

سورس و خروجی خصوصی Auto‑Deployer عمداً از این مخزن حذف شده‌اند.

</div>

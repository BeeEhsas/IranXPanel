# IranX Panel — نصب دستی روی Cloudflare

<div dir="rtl" align="right">

این مخزن فقط برای نصب دستی نسخهٔ **Cloudflare Workers + D1** است. کد و فایل‌های Auto‑Deployer در این مخزن عمومی قرار ندارند.

English: [README.md](README.md)

## فایل‌ها

- `index.js`: فایل آمادهٔ Worker پنل؛ محتوای آن را داخل ویرایشگر Cloudflare Dashboard قرار دهید.
- `schema.sql`: فایل ساخت جدول‌های D1؛ محتوای آن را در D1 Console اجرا کنید.

## نصب پنل

### ۱. ساخت Worker

در Cloudflare Dashboard وارد مسیر **Workers & Pages** شوید، یک Worker جدید بسازید و محتوای فایل `index.js` را داخل ویرایشگر آن قرار دهید.

سپس در تنظیمات Worker این Compatibility flag را فعال کنید:

```text
nodejs_compat
```

### ۲. ساخت دیتابیس D1

از مسیر **D1 SQL Database** یک دیتابیس جدید بسازید. سپس وارد Console آن شوید و محتوای فایل `schema.sql` را اجرا کنید.

### ۳. اتصال دیتابیس به Worker

در مسیر زیر یک D1 binding اضافه کنید:

```text
Settings → Bindings → Add → D1 Database
```

مقادیر را این‌طور وارد کنید:

```text
Variable name: DB
D1 database: نام دیتابیسی که ساختید
```

نام binding باید دقیقاً `DB` باشد.

### ۴. تنظیم Secretها

در مسیر **Settings → Variables and Secrets** این دو Secret را اضافه کنید:

- `SECRET_KEY`: یک رشتهٔ تصادفی و قدرتمند برای امضای نشست‌ها
- `ADMIN_PASSWORD`: رمز مدیر؛ حداقل ۸ کاراکتر و شامل حرف بزرگ، حرف کوچک و عدد

مقادیر محرمانه را داخل README، کد یا ریپوی گیت‌هاب ننویسید.

### ۵. تنظیم متغیرها

این Environment Variableها را اضافه کنید:

```text
PANEL_TITLE = IranX Panel
DOMAIN = نام-worker.نام-حساب.workers.dev
RELAY_DOMAIN = نام-worker.نام-حساب.workers.dev
WS_PATH = ws
XHTTP_PATH = xh
DEVICE_WINDOW = 300
LIVE_WINDOW = 60
SESSION_IDLE = 90
```

برای `DOMAIN` و `RELAY_DOMAIN` فقط نام هاست را بنویسید؛ عبارت `https://` و مسیر انتهایی را وارد نکنید.

### ۶. انتشار پنل

روی **Deploy** بزنید و سپس آدرس نهایی را باز کنید:

```text
https://نام-worker.نام-حساب.workers.dev
```

نام کاربری مدیر همیشه است:

```text
admin
```

رمز ورود همان مقداری است که در Secret با نام `ADMIN_PASSWORD` تعیین کرده‌اید.

## نکات مهم

- هیچ API Token، `SECRET_KEY`، رمز مدیر یا شناسهٔ خصوصی حساب Cloudflare را commit نکنید.
- آدرس `workers.dev` ممکن است در بعضی شبکه‌ها، از جمله ایران، مسدود باشد.
- VLESS روی WebSocket مسیر عملیاتی نسخهٔ Cloudflare است.
- XHTTP در تنظیمات وجود دارد، اما پیاده‌سازی داخلی آن هنوز کامل و آمادهٔ استفادهٔ production نیست.
- Workers Free محدودیت اتصال هم‌زمان و سهمیهٔ درخواست دارد.
- استفاده از Cloudflare Workers تابع شرایط Cloudflare و قوانین محل است.

</div>

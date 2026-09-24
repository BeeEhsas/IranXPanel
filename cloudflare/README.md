# IranX Panel — نصب دستی Cloudflare

این پوشه فقط برای نصب دستی نسخهٔ **Cloudflare Workers + D1** است. فایل Auto‑Deployer به‌صورت عمومی منتشر نشده است.

## فایل‌ها

- `index.js`: Worker آمادهٔ پنل؛ محتوای آن را داخل Cloudflare Dashboard Worker قرار دهید.
- `schema.sql`: ساخت جدول‌های پنل؛ آن را داخل D1 Console اجرا کنید.

## نصب

### ۱. ساخت Worker

در Cloudflare Dashboard وارد **Workers & Pages** شوید، یک Worker جدید بسازید و `index.js` را در ویرایشگر آن قرار دهید.

Compatibility flag زیر را فعال کنید:

```text
nodejs_compat
```

### ۲. ساخت D1

از مسیر **D1 SQL Database** یک دیتابیس بسازید، سپس فایل `schema.sql` را در Console آن اجرا کنید.

### ۳. اتصال D1 به Worker

در **Settings → Bindings → Add → D1 Database** یک binding بسازید:

```text
Variable name: DB
D1 database: نام دیتابیسی که ساختید
```

نام binding باید دقیقاً `DB` باشد.

### ۴. Secretها

در **Settings → Variables and Secrets** دو Secret اضافه کنید:

- `SECRET_KEY`: یک رشتهٔ تصادفی قوی
- `ADMIN_PASSWORD`: رمز مدیر شامل حرف بزرگ، حرف کوچک و عدد؛ حداقل ۸ کاراکتر

### ۵. متغیرها

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

برای `DOMAIN` و `RELAY_DOMAIN` پروتکل `https://` و مسیر انتهایی را وارد نکنید.

### ۶. انتشار

Worker را Deploy کنید و سپس آدرس `workers.dev` را باز کنید:

```text
https://نام-worker.نام-حساب.workers.dev
```

اطلاعات ورود اولیه:

```text
Username: admin
Password: مقدار ADMIN_PASSWORD
```

## نکات

- توکن API و اطلاعات حساب Cloudflare را داخل این ریپو قرار ندهید.
- `workers.dev` ممکن است در بعضی شبکه‌ها مسدود باشد.
- VLESS WebSocket مسیر عملیاتی نسخهٔ Cloudflare است؛ XHTTP در این نسخه هنوز کامل نیست.
- استفاده از Workers تابع شرایط Cloudflare و قوانین محل است.

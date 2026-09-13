# کیف‌یار 💰

کیف‌یار یک برنامه ساده برای مدیریت امور مالی شخصی است.

## امکانات

- ثبت‌نام و ورود کاربران
- خروج از حساب
- مدیریت پروفایل
- تغییر رمز عبور
- حذف حساب
- مدیریت موجودی کیف پول
- افزایش موجودی
- کاهش موجودی
- ثبت درآمد
- ثبت هزینه
- دسته‌بندی تراکنش‌ها
- جستجوی تراکنش‌ها
- فیلتر تراکنش‌ها
- فیلتر بر اساس تاریخ
- گزارش‌های مالی
- اعلان‌های مالی
- نمایش موجودی فعلی
- نمایش مجموع درآمد
- نمایش مجموع هزینه
- نمایش تعداد تراکنش‌ها
- داشبورد اصلی
- طراحی واکنش‌گرا برای موبایل و دسکتاپ

## ساختار پروژه

```text
KifYar/
│
├── backend/
│   ├── __init__.py
│   ├── auth.py
│   ├── database.py
│   ├── main.py
│   └── session.py
│
├── frontend/
│   ├── index.html
│   ├── login.html
│   ├── profile.html
│   ├── settings.html
│   ├── edit-profile.html
│   ├── change-password.html
│   ├── delete-account.html
│   ├── wallet.html
│   ├── transactions.html
│   ├── reports.html
│   └── notifications.html
│
├── .gitignore
├── requirements.txt
└── README.md
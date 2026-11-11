@echo off
chcp 65001 >nul
title Máy Chủ Cổng Thông Tin Công Đoàn YPMV - Yamaha Motor Việt Nam
echo ====================================================================
echo   ĐANG KHỞI ĐỘNG MÁY CHỦ HOST CÔNG ĐOÀN YPMV TRÊN MÁY CỦA BẠN...
echo   Mở trình duyệt tại địa chỉ: http://localhost:3000
echo ====================================================================
start http://localhost:3000
node server.js
pause

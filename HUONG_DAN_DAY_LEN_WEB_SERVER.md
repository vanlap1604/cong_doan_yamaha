# HƯỚNG DẪN ĐẨY TRANG WEB CÔNG ĐOÀN YPMV LÊN WEB SERVER (CHẠY ONLINE 24/7)

Dự án của bạn tại `C:\Users\Admin\.gemini\antigravity\scratch\yamaha-union-portal` đã được đóng gói hoàn chỉnh với [server.js](./server.js), [package.json](./package.json), [render.yaml](./render.yaml) và [Dockerfile](./Dockerfile).

Vì trang web có **Máy chủ bảo mật ẩn danh sách đoàn viên & lưu cơ sở dữ liệu vào `./data/database.json`**, bạn có **3 cách phổ biến nhất** để đưa lên Web Server tùy theo nhu cầu của công ty:

---

## CÁCH 1: Đưa lên Web Server Đám Mây Miễn Phí / Chi Phí Thấp (Render.com hoặc Railway.app) — Khuyên dùng nếu chưa có máy chủ riêng

Bạn **không cần cài đặt phần mềm phức tạp**, chỉ cần tải các file lên GitHub bằng trình duyệt web rồi kết nối với Render hoặc Railway:

### Bước 1: Đưa thư mục code lên GitHub (Kéo thả trên trình duyệt)
1. Truy cập **https://github.com** -> Đăng ký / Đăng nhập tài khoản.
2. Nhấn nút **`+`** (góc trên bên phải) -> chọn **New repository**.
3. Đặt tên kho lưu trữ là `cong-doan-ypmv`, chọn chế độ **Private** (Riêng tư để bảo mật dữ liệu công ty) -> Nhấn **Create repository**.
4. Nhấn vào dòng chữ **"uploading an existing file"** trên màn hình.
5. Mở thư mục `C:\Users\Admin\.gemini\antigravity\scratch\yamaha-union-portal` trên máy tính của bạn, bôi đen toàn bộ các file (`server.js`, `index.html`, `styles.css`, `app.js`, `package.json`, `render.yaml`, `Dockerfile`, thư mục `data`) và **kéo thả vào trình duyệt**.
6. Nhấn nút xanh **Commit changes**.

### Bước 2: Kết nối với Web Server (Render.com hoặc Railway.app)
- **Với Render.com:**
  1. Vào **https://render.com** -> Chọn **Sign in with GitHub**.
  2. Nhấn **New +** -> Chọn **Web Service** -> Chọn kho `cong-doan-ypmv` vừa tạo.
  3. Render sẽ tự nhận diện cấu hình Node.js (`Start Command: node server.js`).
  4. Nhấn **Create Web Service**. Sau 1 phút bạn sẽ nhận được đường link chính thức dạng: `https://cong-doan-ypmv.onrender.com`.
- **Với Railway.app (Lưu trữ dữ liệu bền vững tốt hơn):**
  1. Vào **https://railway.app** -> Chọn **Login with GitHub**.
  2. Nhấn **New Project** -> **Deploy from GitHub repo** -> Chọn `cong-doan-ypmv`.
  3. Trong mục **Settings -> Networking**, nhấn **Generate Domain** để lấy tên miền `.up.railway.app` (hoặc gắn tên miền riêng của công ty).

---

## CÁCH 2: Đưa lên Máy Chủ Nội Bộ / VPS Windows Server hoặc Linux của Công ty (IT Công ty quản lý)

Nếu phòng IT của công ty YPMV có sẵn máy chủ **Windows Server** hoặc **VPS Ubuntu/Linux**:

1. **Copy nguyên thư mục** `yamaha-union-portal` sang máy chủ (qua Remote Desktop, USB hoặc FileZilla SFTP).
2. Cài đặt **Node.js** (bản LTS từ https://nodejs.org) trên máy chủ đó.
3. Chạy lệnh khởi động dịch vụ chạy ngầm 24/7:
   - Trên Windows Server: Nhấp đúp chạy `CHAY_HOST_TREN_MAY.bat` hoặc dùng `pm2`:
     ```bash
     npm install -g pm2
     pm2 start server.js --name "cong-doan-ypmv"
     pm2 save
     ```
4. Mở cổng (Port) `3000` trên tường lửa máy chủ (hoặc trỏ tên miền nội bộ/công khai qua Nginx/IIS Reverse Proxy về `http://localhost:3000`).

---

## CÁCH 3: Mở đường dẫn Internet ngay lập tức từ chính máy tính hiện tại của bạn (Không cần thuê Server)

Nếu bạn muốn gửi link cho đoàn viên truy cập từ mạng 4G/Internet ngay bây giờ mà máy chủ vẫn đặt trên máy tính của bạn:
1. Giữ cửa sổ `CHAY_HOST_TREN_MAY.bat` đang chạy (`http://localhost:3000`).
2. Sử dụng công cụ **Cloudflare Tunnel (`cloudflared`)** hoặc **Ngrok**:
   - Chạy lệnh: `cloudflared tunnel --url http://localhost:3000`
   - Hệ thống sẽ cấp ngay một đường link `https://xxxx.trycloudflare.com` để mọi người truy cập từ bất kỳ đâu trên điện thoại/máy tính.

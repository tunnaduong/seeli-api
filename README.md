# SEELI API

Backend cho app SEELI — *See more. Live more.*

- **Node.js 24 + Fastify + SQLite** (SQLite có sẵn trong Node → không có module native, build trên Raspberry Pi arm64 không lỗi).
- Toàn bộ dữ liệu (database + ảnh) nằm trong thư mục `data/`. Sao lưu = copy thư mục này.
- Chạy bằng **Docker Compose**, chỉ mở cổng ở `127.0.0.1`; aaPanel (nginx) làm reverse proxy + SSL.

## Server bảo vệ triết lý của app
- Link ảnh (`photoUrl`) **chỉ được trả về khi đã đến ngày gặp lại** (~27–37 ngày, ngẫu nhiên). Link có chữ ký, hết hạn sau 1 giờ.
- Bạn bè **không bao giờ** nhận được địa điểm chụp.
- Kết bạn chỉ bằng **mã mời 8 ký tự trong QR** (bí mật, đổi được) — không thể thêm ai chỉ bằng tên người dùng.
- Bình luận ("góc nhìn"): người đăng thấy tất cả, người bình luận chỉ thấy của mình. Không có like / follower / lượt xem.
- Ghi chú riêng về bạn bè (memo) chỉ người viết thấy.

## Deploy lên aaPanel (Raspberry Pi)

Đã deploy sẵn ở `/www/wwwroot/seeli-api` (container `seeli-api`, cổng `127.0.0.1:8790`).

### Đang chạy tại `https://seeli-api.tunnaduong.com`
- Cloudflare Tunnel (wildcard `*.tunnaduong.com`) → nginx của aaPanel cổng 80 → `127.0.0.1:8790`. SSL do Cloudflare đảm nhận.
- File nginx: `/www/server/panel/vhost/nginx/seeli-api.tunnaduong.com.conf` (viết tay, nên **không hiện trong danh sách Website của aaPanel**). Nếu muốn quản lý trong aaPanel: tạo site cùng tên miền với reverse proxy `http://127.0.0.1:8790`, aaPanel sẽ ghi đè file này.

### 1. (Server khác) Tạo tên miền + reverse proxy trong aaPanel
1. Trỏ DNS tên miền (ví dụ `seeli-api.tunnaduong.com`) về server.
2. aaPanel → **Website → Add site** → nhập tên miền, PHP: *Static*.
3. Mở site → **Reverse proxy → Add** → Target URL: `http://127.0.0.1:8790`.
4. **SSL → Let's Encrypt** → bật **Force HTTPS**.
5. Sửa `/www/wwwroot/seeli-api/.env`: `PUBLIC_URL=https://seeli-api.tunnaduong.com`, rồi chạy `sudo bash deploy.sh`.
6. Kiểm tra: `https://seeli-api.tunnaduong.com/v1/health`.

> Ảnh tối đa 8 MB: trong cấu hình nginx của site, đặt `client_max_body_size 10m;` nếu bị lỗi 413.

### 2. Tự động deploy khi push GitHub (dùng `aapanel-deploy-action`)
Tạo repo GitHub cho thư mục này, rồi trong aaPanel **Webhook** thêm lệnh:

```bash
cd /www/wwwroot/seeli-api && sudo bash deploy.sh
```

`deploy.sh` sẽ: `git reset --hard origin/main` → tạo `.env` (với `JWT_SECRET` ngẫu nhiên) nếu chưa có → `docker compose up -d --build` → chờ `/v1/health`.

Workflow GitHub giống các project khác:

```yaml
name: Auto Deploy to aaPanel
on: { push: { branches: [main] } }
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: tunnaduong/aapanel-deploy-action@main
        with:
          panel_url: https://panel.example.com
          webhook_key: ${{ secrets.AAPANEL_WEBHOOK_KEY }}
```

### Lệnh hữu ích (trên server)
```bash
cd /www/wwwroot/seeli-api
sudo docker compose logs -f seeli-api      # xem log
sudo docker compose restart seeli-api       # khởi động lại
sudo tar czf ~/seeli-backup-$(date +%F).tgz data   # sao lưu
```

## Trang quản trị — `/admin`
**https://seeli-api.tunnaduong.com/admin**

- **Tổng quan:** số người dùng, ảnh, kết nối, báo cáo đang mở, dung lượng ổ đĩa, trạng thái chế độ demo, nhật ký thao tác.
- **Người dùng:** tìm kiếm; khoá / mở khoá (khoá = đăng xuất ngay + không đăng nhập được); đăng xuất mọi thiết bị; xoá vĩnh viễn (phải gõ lại tên người dùng, xoá luôn ảnh).
- **Báo cáo:** xem báo cáo từ app, đánh dấu đã xử lý / bỏ qua / mở lại, khoá người bị báo cáo.
- Cố ý **không** hiện ảnh, lời ghi chú, địa điểm, bình luận hay ghi chú riêng của người dùng.

Mật khẩu nằm trong `.env` trên server (tự tạo khi deploy lần đầu):

```bash
ssh pi@<server> 'sudo grep ADMIN_PASSWORD /www/wwwroot/seeli-api/.env'
```

Đổi mật khẩu: sửa `ADMIN_PASSWORD` trong `.env` rồi chạy `sudo bash deploy.sh` (phiên đăng nhập cũ hết hiệu lực ngay).
Bảo mật: cookie HttpOnly + Secure + SameSite=Strict, phiên 12 giờ, khoá đăng nhập sau 5 lần sai (15 phút). Muốn chặt hơn nữa có thể bật **Cloudflare Access** cho đường dẫn `/admin`.

## Cấu hình (`.env`)
| Biến | Ý nghĩa |
|---|---|
| `JWT_SECRET` | Khoá ký token (bắt buộc, `openssl rand -hex 32`) |
| `PUBLIC_URL` | URL công khai của API, dùng cho link ảnh |
| `HOST_PORT` | Cổng trên server (mặc định 8790, chỉ 127.0.0.1) |
| `REVEAL_MIN_DAYS` / `REVEAL_MAX_DAYS` | Khoảng ngày ảnh quay lại (27–37) |
| `ALLOW_DEMO` | Cho phép chế độ demo (ảnh quay lại sau ~1 phút). **Tắt khi ra mắt.** |
| `MAX_PHOTO_MB` | Dung lượng ảnh tối đa |
| `ADMIN_PASSWORD` | Mật khẩu trang `/admin` (để trống = tắt trang quản trị) |

## API (`/v1`)
| Method | Path | Mô tả |
|---|---|---|
| POST | `/auth/signup`, `/auth/login` | Trả `{ token, user }` |
| POST | `/auth/logout` | Đăng xuất mọi thiết bị |
| GET/PATCH/DELETE | `/me` | Hồ sơ / sửa / xoá tài khoản (xoá cả ảnh) |
| POST | `/me/invite/rotate` | Đổi mã mời |
| GET | `/invites/:code` | Xem trước người có mã mời |
| GET/POST | `/friends` | Danh sách / kết bạn bằng `{ code }` |
| PATCH/DELETE | `/friends/:id` | Sửa memo / huỷ kết bạn |
| POST | `/friends/:id/block` · GET `/blocks` · DELETE `/blocks/:id` | Chặn |
| POST | `/reports` | Báo cáo |
| GET/POST | `/moments` | Ảnh của tôi / đăng ảnh (multipart: `photo`, `note`, `placeName`, `audience`, `createdAt`, `demo`) |
| POST | `/moments/:id/reunite` | Đánh dấu đã gặp lại (chỉ khi đã đến hạn) |
| PATCH/DELETE | `/moments/:id` | Lưu góc nhìn mới (`reflection`) / xoá |
| GET | `/feed` | Khoảnh khắc "My Circle" của bạn bè |
| GET | `/moments/:id/comments` · PUT/DELETE `/moments/:id/comment` | Góc nhìn |
| GET | `/photos/:id?exp&sig` | Ảnh (link có chữ ký) |

## Phát triển
```bash
npm install
npm run dev     # http://localhost:8790
npm test
```

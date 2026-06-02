# F&G WAF — Hướng Dẫn Toàn Diện (Bản Giải Thích Dễ Hiểu)

> **F&G WAF** (tên kỹ thuật: `mini-waf`) · Tường Lửa Ứng Dụng Web · **Phiên bản 1.1.0** · Viết bằng ngôn ngữ Rust (ấn bản 2024) · Dựa trên nền Cloudflare Pingora
>
> 📖 **Tài liệu này được viết cho mọi người** — kể cả khi bạn *không phải dân kỹ thuật*. Mỗi thuật ngữ chuyên ngành đều có chú thích bằng tiếng Việt dễ hiểu, kèm ví dụ và sơ đồ minh hoạ. Nếu gặp một từ lạ, hãy tra ngay trong [Bảng Thuật Ngữ](#-bảng-thuật-ngữ-tra-cứu-nhanh) ở đầu tài liệu.
>
> 📚 **Muốn đi sâu hơn?** Xem tài liệu đồng hành [**46 Tính Năng Chi Tiết (Bản Kỹ Thuật Mở Rộng)**](./F&G-WAF-46-tinh-nang-chi-tiet-VI.md) — phân tích từng yêu cầu chức năng FR-001 → FR-046 kèm 31 sơ đồ kỹ thuật.

---

## 📑 Mục Lục

**Phần dành cho người mới bắt đầu**
- [0. WAF Là Gì? — Giải Thích Bằng Đời Thường](#0-waf-là-gì--giải-thích-bằng-đời-thường)
- [📚 Bảng Thuật Ngữ (Tra Cứu Nhanh)](#-bảng-thuật-ngữ-tra-cứu-nhanh)

**Phần kỹ thuật chi tiết**
1. [Giới Thiệu Tổng Quan](#1-giới-thiệu-tổng-quan)
2. [Kiến Trúc Hệ Thống](#2-kiến-trúc-hệ-thống)
3. [Cài Đặt & Triển Khai](#3-cài-đặt--triển-khai)
4. [Hướng Dẫn Sử Dụng Trang Quản Trị (Admin UI)](#4-hướng-dẫn-sử-dụng-trang-quản-trị-admin-ui)
5. [Dây Chuyền Kiểm Tra An Ninh (Pipeline)](#5-dây-chuyền-kiểm-tra-an-ninh-pipeline)
6. [Danh Mục Quy Tắc Bảo Vệ](#6-danh-mục-quy-tắc-bảo-vệ)
7. [Tham Chiếu Cấu Hình](#7-tham-chiếu-cấu-hình)
8. [Phân Cụm & Khả Dụng Cao (Cluster/HA)](#8-phân-cụm--khả-dụng-cao-clusterha)
9. [Tham Chiếu REST API](#9-tham-chiếu-rest-api)
10. [Tham Chiếu Dòng Lệnh (CLI)](#10-tham-chiếu-dòng-lệnh-cli)
11. [Thực Hành Bảo Mật Tốt Nhất](#11-thực-hành-bảo-mật-tốt-nhất)
12. [Xử Lý Sự Cố Thường Gặp](#12-xử-lý-sự-cố-thường-gặp)
- [Phụ Lục A: Bản Đồ Tính Năng (FR)](#phụ-lục-a-bản-đồ-tính-năng-fr)

---

## 0. WAF Là Gì? — Giải Thích Bằng Đời Thường

### 0.1 Hình dung đơn giản nhất

Hãy tưởng tượng website (trang web) hoặc ứng dụng của bạn là một **toà nhà văn phòng**. Mỗi ngày có rất nhiều người ra vào: khách hàng thật, nhân viên, người giao hàng… nhưng cũng có thể có **kẻ trộm, kẻ phá hoại** trà trộn vào.

**WAF** (Web Application Firewall — *Tường Lửa Ứng Dụng Web*) chính là **đội bảo vệ đứng ngay cửa ra vào**. Mọi người muốn vào toà nhà đều phải đi qua chốt bảo vệ này trước. Đội bảo vệ sẽ:

- 👀 **Nhìn mặt, kiểm tra giấy tờ** của từng người (kiểm tra từng yêu cầu truy cập).
- 🚫 **Chặn ngay** những kẻ có dấu hiệu nguy hiểm (chặn tấn công).
- ✅ **Cho qua** những người bình thường (cho phép truy cập hợp lệ).
- 📓 **Ghi sổ** lại ai đã đến, ai bị chặn, lý do vì sao (ghi nhật ký an ninh).

F&G WAF làm đúng việc đó cho website, nhưng với **tốc độ hàng chục nghìn lượt mỗi giây** và **hoàn toàn tự động**.

```mermaid
flowchart LR
    User([👤 Người dùng thật]):::good
    Hacker([🦹 Kẻ tấn công]):::bad
    WAF{{🛡️ F&G WAF<br/>Bảo vệ ở cửa}}:::waf
    Web[🏢 Website của bạn<br/>máy chủ thật]:::server

    User -->|yêu cầu hợp lệ| WAF
    Hacker -->|yêu cầu độc hại| WAF
    WAF -->|✅ cho qua| Web
    WAF -.->|🚫 chặn lại| Hacker

    classDef good fill:#d4edda,stroke:#28a745,color:#155724
    classDef bad fill:#f8d7da,stroke:#dc3545,color:#721c24
    classDef waf fill:#cce5ff,stroke:#0066cc,color:#004085
    classDef server fill:#fff3cd,stroke:#ffc107,color:#856404
```

> 💡 **Điểm mấu chốt:** Người dùng không bao giờ nói chuyện trực tiếp với máy chủ website. Họ luôn nói chuyện với WAF trước. WAF kiểm tra xong mới *chuyển tiếp* yêu cầu vào trong. Nhờ vậy, máy chủ thật được giấu kín và bảo vệ phía sau.

### 0.2 "Reverse Proxy" nghĩa là gì?

**Reverse proxy** *(máy chủ trung gian đứng trước)* giống như **lễ tân của toà nhà**. Khách không tự đi vào phòng làm việc; họ nói với lễ tân "tôi cần gặp phòng Kế toán", rồi lễ tân mới dẫn đường hoặc chuyển lời.

F&G WAF vừa là **bảo vệ** (kiểm tra an ninh) vừa là **lễ tân** (nhận yêu cầu rồi chuyển vào đúng máy chủ bên trong). Một WAF có thể đứng trước **nhiều website cùng lúc** — giống một lễ tân phục vụ nhiều phòng ban.

### 0.3 Những loại "kẻ xấu" mà WAF chặn

Trên Internet có rất nhiều kiểu tấn công. Dưới đây là vài loại phổ biến, giải thích thật đơn giản (chi tiết kỹ thuật xem ở [Mục 5](#5-dây-chuyền-kiểm-tra-an-ninh-pipeline) và [Bảng Thuật Ngữ](#-bảng-thuật-ngữ-tra-cứu-nhanh)):

| Kiểu tấn công | Ví von đời thường | WAF làm gì |
|---|---|---|
| **SQL Injection** | Kẻ gian đưa "tờ giấy có phép thuật" để lừa thủ kho mở cả kho dữ liệu | Phát hiện câu lệnh cơ sở dữ liệu trá hình và chặn |
| **XSS** | Dán mẩu giấy độc lên bảng thông báo để hại người đọc sau | Phát hiện đoạn mã JavaScript chèn lén và chặn |
| **DDoS / CC** | Hàng vạn người giả kéo đến cửa cùng lúc để làm nghẽn lối vào | Đếm tần suất, chặn kẻ "gõ cửa" quá nhanh |
| **Bot / Scanner** | Kẻ đi dò từng cánh cửa xem cửa nào quên khoá | Nhận diện công cụ dò quét tự động và chặn |
| **SSRF** | Lừa nhân viên bên trong tự đi lấy đồ ở nơi cấm | Chặn yêu cầu trỏ tới địa chỉ nội bộ/nguy hiểm |
| **Lộ dữ liệu** | Nhân viên lỡ tay đưa hồ sơ mật ra ngoài | Quét và che (redact) thông tin nhạy cảm |

### 0.4 Vì sao chọn F&G WAF?

- ⚡ **Nhanh:** Viết bằng **Rust** *(một ngôn ngữ lập trình rất nhanh và an toàn bộ nhớ)*, chạy trên nền **Pingora** *(bộ khung proxy của Cloudflare, phục vụ hàng nghìn tỉ lượt truy cập mỗi ngày)*.
- 📦 **Gọn:** Toàn bộ hệ thống nằm trong **một file chạy duy nhất** tên là `waf`. Không cần cài đặt rườm rà.
- 🧠 **Thông minh:** Hơn **650 quy tắc** bảo vệ dựng sẵn, cộng với khả năng **tự học điểm rủi ro** cho từng người truy cập.
- 🖥️ **Dễ quản lý:** Có sẵn **trang quản trị web** đẹp mắt, xem được mọi thứ theo thời gian thực.
- 🔗 **Mở rộng được:** Có thể chạy **nhiều máy cùng lúc** (cluster) để không bao giờ "sập".

---

## 📚 Bảng Thuật Ngữ (Tra Cứu Nhanh)

> Đây là phần quan trọng nhất cho người không chuyên. Mỗi khi gặp một từ lạ trong tài liệu, hãy quay lại đây. Các thuật ngữ được nhóm theo chủ đề.

### A. Khái niệm Web & Mạng cơ bản

| Thuật ngữ | Giải thích dễ hiểu |
|---|---|
| **Request** (yêu cầu) | Một lần trình duyệt "hỏi" máy chủ điều gì đó — ví dụ "cho tôi xem trang chủ", "đăng nhập giúp tôi". Mỗi cú nhấp chuột thường tạo ra một hoặc nhiều request. |
| **Response** (phản hồi) | Câu trả lời mà máy chủ gửi lại cho request — ví dụ nội dung trang web, ảnh, dữ liệu. |
| **Client** (máy khách) | Bên *gửi* request: thường là trình duyệt của người dùng, hoặc ứng dụng điện thoại. |
| **Server / Backend / Upstream** (máy chủ đích) | Máy tính thật chứa website/ứng dụng, nằm *phía sau* WAF. WAF chuyển request hợp lệ tới đây. Ba từ này trong tài liệu gần như đồng nghĩa. |
| **Proxy** | Máy đứng giữa làm trung gian truyền tin. **Reverse proxy** đứng trước máy chủ (bảo vệ máy chủ). |
| **HTTP / HTTPS** | "Ngôn ngữ" mà trình duyệt và máy chủ dùng để trò chuyện. **HTTPS** là HTTP có **mã hoá** (khoá ổ móc 🔒), kẻ nghe lén không đọc được. |
| **HTTP/1.1, HTTP/2, HTTP/3** | Ba *phiên bản* của ngôn ngữ HTTP. Phiên bản càng mới càng nhanh. HTTP/3 dùng công nghệ **QUIC**. |
| **QUIC** | Công nghệ truyền dữ liệu mới (nền của HTTP/3), nhanh và ổn định hơn, đặc biệt trên mạng di động. |
| **TLS / SSL** | Lớp mã hoá tạo nên chữ "S" trong HTTPS. "Kết thúc TLS" (TLS termination) = WAF tự giải mã lớp bảo mật để đọc và kiểm tra nội dung. |
| **Chứng chỉ (Certificate)** | "Giấy chứng minh thư" của website, để trình duyệt tin tưởng đây đúng là website thật. **Let's Encrypt** là dịch vụ cấp giấy này *miễn phí, tự động*. |
| **Domain / Hostname** | Tên website, ví dụ `example.com`. |
| **Port (cổng)** | "Số cửa" trên một máy chủ. Ví dụ cửa **80** cho HTTP, cửa **443** cho HTTPS. |
| **IP / IPv4 / IPv6** | "Địa chỉ nhà" của một máy trên Internet, ví dụ `203.0.113.5`. IPv6 là dạng địa chỉ mới, dài hơn. |
| **CIDR** | Cách viết gọn *một dải nhiều địa chỉ IP*. Ví dụ `10.0.0.0/8` nghĩa là "tất cả IP bắt đầu bằng 10.x.x.x". |
| **URL / Path** | **URL** là đường dẫn đầy đủ tới một trang. **Path** là phần đường dẫn sau tên miền, ví dụ `/login`, `/api/users`. |
| **Header (tiêu đề)** | Thông tin phụ kèm theo mỗi request, ví dụ trình duyệt nào, ngôn ngữ gì, đến từ trang nào (`Referer`). |
| **Cookie** | Mẩu dữ liệu nhỏ trình duyệt giữ giúp website "nhớ" bạn (ví dụ nhớ đã đăng nhập). |
| **Payload** | "Nội dung thực" của request — chính là phần kẻ tấn công thường giấu mã độc vào. |

### B. Các kiểu tấn công (mối đe doạ)

| Thuật ngữ | Giải thích dễ hiểu |
|---|---|
| **SQL Injection (SQLi)** | Chèn câu lệnh cơ sở dữ liệu độc hại vào ô nhập liệu để đánh cắp/xoá dữ liệu. Ví dụ gõ `' OR 1=1 --` vào ô đăng nhập. |
| **XSS** (Cross-Site Scripting) | Chèn đoạn mã JavaScript độc vào trang để chạy trên trình duyệt của nạn nhân khác (đánh cắp phiên đăng nhập…). |
| **RCE** (Remote Code Execution) | Lừa máy chủ *chạy lệnh* của kẻ tấn công — nguy hiểm nhất, có thể chiếm toàn bộ máy. |
| **LFI / RFI** | Lừa máy chủ *đọc file nội bộ* (LFI) hoặc *tải file từ xa* (RFI) không được phép. |
| **Path Traversal** (đi lạc thư mục) | Dùng `../../` để "leo" ra khỏi thư mục cho phép và đọc file cấm như `/etc/passwd`. |
| **SSRF** (Server-Side Request Forgery) | Lừa *chính máy chủ* tự gửi request tới nơi mà kẻ tấn công không trực tiếp tới được (ví dụ địa chỉ nội bộ, dịch vụ đám mây). |
| **SSTI** | Tấn công vào "khuôn mẫu" tạo trang (template), ví dụ gõ `${7*7}` mà máy chủ lại tính ra `49` → có lỗ hổng. |
| **XXE** | Lợi dụng cách máy chủ xử lý file XML để đọc trộm dữ liệu. |
| **Deserialization** | Lợi dụng cách máy chủ "giải nén" dữ liệu đối tượng để chạy mã độc. |
| **Prototype Pollution** | Tấn công đặc thù của JavaScript, "đầu độc" cấu trúc đối tượng gốc. |
| **WebShell** | File độc kẻ tấn công cài lên máy chủ để điều khiển từ xa. |
| **DDoS** | Tấn công từ chối dịch vụ phân tán: huy động *rất nhiều máy* dội request làm sập website. |
| **CC Attack** | Một dạng DDoS nhắm vào các trang "nặng" (như tìm kiếm) để vắt cạn tài nguyên. |
| **Bot** | Chương trình tự động giả làm người. Có **bot tốt** (Google dò web) và **bot xấu** (đi cào dữ liệu, dò mật khẩu). |
| **Scanner** | Công cụ tự động *dò quét* lỗ hổng (Nikto, Nmap, sqlmap, Burp…). Như kẻ đi thử từng ổ khoá. |
| **Credential Stuffing** | Dùng kho tài khoản/mật khẩu rò rỉ thử hàng loạt để chiếm tài khoản. |
| **Brute Force** | "Dò mò" mật khẩu bằng cách thử rất nhiều lần. |
| **Honeypot** (bẫy mật ong) | Đường dẫn "mồi" giả (như `/.git/config`) — người bình thường không bao giờ vào; ai chạm vào gần như chắc chắn là kẻ dò quét → chặn ngay. |

### C. Cơ chế phòng thủ của WAF

| Thuật ngữ | Giải thích dễ hiểu |
|---|---|
| **Rule (quy tắc)** | Một "điều luật" mô tả dấu hiệu nguy hiểm và hành động xử lý. WAF có sẵn hơn 650 quy tắc. |
| **OWASP CRS** | "Bộ luật mẫu chuẩn quốc tế" (Core Rule Set) do tổ chức an ninh OWASP biên soạn, được nhiều WAF dùng. |
| **CVE** | Mã định danh một lỗ hổng bảo mật *đã được công bố* trên toàn cầu (ví dụ `CVE-2021-44228` = lỗ hổng Log4Shell). |
| **Regex** (biểu thức chính quy) | Một "khuôn mẫu tìm kiếm chuỗi" mạnh mẽ, giúp quy tắc nhận ra payload độc dù biến đổi nhiều kiểu. |
| **libinjection** | Thư viện chuyên dụng phát hiện SQLi/XSS rất chính xác, ít báo nhầm. |
| **Aho-Corasick** | Thuật toán tìm *cùng lúc hàng nghìn từ khoá* trong một văn bản cực nhanh — dùng để quét dữ liệu nhạy cảm. |
| **Rate Limiting** (giới hạn tần suất) | Giới hạn số request mỗi giây từ một nguồn — "mỗi người chỉ được gõ cửa X lần/phút". |
| **Token Bucket** (xô token) | Cách tính tần suất: mỗi nguồn có một "xô" chứa token; mỗi request tiêu 1 token; xô được đổ đầy dần. Hết token → bị chặn. Cho phép "bùng" ngắn nhưng giới hạn về dài. |
| **Sliding Window** (cửa sổ trượt) | Cách tính tần suất theo "X request trong Y giây gần nhất", chính xác hơn đếm theo phút cứng. |
| **Risk Score (điểm rủi ro)** | "Điểm nghi ngờ" tích luỹ cho mỗi người truy cập. Nhiều dấu hiệu xấu → điểm cao → bị thách thức hoặc chặn. |
| **Challenge (thách thức)** | Thay vì chặn thẳng, WAF bắt trình duyệt "giải một câu đố" (ví dụ **proof-of-work** — bắt máy tính làm một phép tính nhỏ tốn thời gian, hoặc **CAPTCHA**). Người thật vượt qua dễ; bot thì tốn kém. |
| **Fail-open / Fail-close** | Khi WAF gặp sự cố nội bộ: **fail-open** = vẫn cho qua (ưu tiên website không gián đoạn); **fail-close** = chặn lại (ưu tiên an toàn). Trang quan trọng (đăng nhập, thanh toán) nên fail-close. |
| **Tier (tầng/lớp ưu tiên)** | WAF chia các đường dẫn thành 4 mức quan trọng (Critical/High/Medium/CatchAll) để áp dụng mức bảo vệ khác nhau. |
| **Allowlist / Blocklist** (danh sách trắng/đen) | **Allowlist** = luôn cho qua; **Blocklist** = luôn chặn. Áp dụng cho IP hoặc đường dẫn URL. |
| **JA3 / JA4** | "Vân tay" của trình duyệt/công cụ dựa trên cách nó bắt tay TLS. Giúp nhận ra cùng một công cụ dù đổi IP. |
| **ASN** | Mã định danh của một nhà mạng/nhà cung cấp. Giúp phân biệt IP từ nhà dân, từ trung tâm dữ liệu, hay từ Tor. |
| **Tor** | Mạng ẩn danh; kẻ tấn công hay dùng để giấu IP thật. |
| **CrowdSec** | Dịch vụ "tình báo an ninh cộng đồng" — chia sẻ danh sách IP xấu giữa nhiều người dùng toàn cầu. |
| **GeoIP** | Tra cứu *quốc gia* của một địa chỉ IP, để có thể chặn theo vùng địa lý. |
| **Shadow Mode (chế độ bóng)** | WAF *tính toán* quyết định nhưng *không thực thi* — chỉ ghi log. Dùng để thử quy tắc mới mà không sợ chặn nhầm khách thật. |

### D. Hạ tầng & vận hành

| Thuật ngữ | Giải thích dễ hiểu |
|---|---|
| **Rust** | Ngôn ngữ lập trình nổi tiếng nhanh và an toàn, được F&G WAF dùng để viết. |
| **Pingora** | Bộ khung proxy hiệu năng cao của Cloudflare (cũng viết bằng Rust) — "động cơ" của WAF. |
| **Crate** | Một "mô-đun"/gói mã nguồn trong Rust. F&G WAF gồm 7 crate ghép lại. |
| **PostgreSQL** | Hệ quản trị cơ sở dữ liệu mạnh mẽ, nơi WAF lưu mọi cấu hình, log, quy tắc. |
| **Valkey / Redis** | Bộ nhớ đệm (cache) tốc độ cao, giúp WAF nhớ tạm dữ liệu để phản hồi nhanh hơn. |
| **Cache** | "Bộ nhớ tạm". Lưu sẵn câu trả lời hay dùng để không phải hỏi lại máy chủ → nhanh hơn, nhẹ tải hơn. |
| **AES-256-GCM** | Thuật toán mã hoá rất mạnh, dùng để cất giữ các giá trị nhạy cảm (như mật khẩu, khoá) *an toàn ngay cả khi nằm trong ổ đĩa*. |
| **JWT** | "Vé thông hành" số mà server cấp sau khi đăng nhập, để các request sau không phải đăng nhập lại. |
| **TOTP / 2FA** | Mã OTP 6 số đổi mỗi 30 giây (như Google Authenticator) — lớp bảo vệ thứ hai khi đăng nhập. |
| **Hot-reload (nạp nóng)** | Cập nhật cấu hình/quy tắc *ngay lập tức* mà **không cần khởi động lại** → không gián đoạn dịch vụ. |
| **Cluster (phân cụm)** | Nhiều máy chủ WAF chạy cùng nhau, chia tải và dự phòng cho nhau. |
| **HA (High Availability)** | "Độ sẵn sàng cao" — hệ thống vẫn chạy dù một máy bị hỏng. |
| **mTLS** | TLS hai chiều: cả hai máy *cùng* trình giấy chứng minh, đảm bảo chỉ các máy được phép mới nói chuyện với nhau. |
| **Raft** | Thuật toán để nhiều máy trong cluster *bầu ra một máy chỉ huy* và thống nhất dữ liệu. |
| **lz4** | Thuật toán nén dữ liệu nhanh, dùng khi đồng bộ quy tắc giữa các máy. |
| **WASM (WebAssembly)** | Định dạng cho phép chạy mã tuỳ biến *an toàn trong hộp cát* (sandbox). |
| **Rhai** | Ngôn ngữ kịch bản nhỏ gọn, cho phép viết quy tắc tuỳ chỉnh linh hoạt ngay trong WAF. |
| **VictoriaLogs** | Hệ thống lưu trữ nhật ký (log) đi kèm, giữ log phục vụ kiểm tra/điều tra. |
| **systemd** | Cơ chế quản lý dịch vụ trên Linux, giúp WAF tự khởi động và tự hồi phục khi lỗi. |
| **Docker / Compose** | Công nghệ "đóng gói" phần mềm vào hộp chạy được mọi nơi. **Compose** giúp khởi động nhiều hộp cùng lúc bằng một lệnh. |

---

## 1. Giới Thiệu Tổng Quan

F&G WAF (tên kỹ thuật `mini-waf`) là **Tường Lửa Ứng Dụng Web kiêm Reverse Proxy** hiệu năng cao, sẵn sàng cho môi trường sản xuất. Toàn bộ hệ thống được đóng gói thành **một file chạy duy nhất** tên là `waf`.

> 🔎 **Lưu ý lịch sử tên gọi:** Dự án từng có tên nội bộ là `prx-waf`. Từ phiên bản hiện tại, file chạy đã được đổi tên thành `waf`. Trong tài liệu này, khi thấy `waf <lệnh>` nghĩa là gọi file chương trình chính.

### 1.1 F&G WAF làm được gì? (tóm tắt cho người quản lý)

```mermaid
mindmap
  root((F&G WAF))
    Bảo vệ tấn công
      SQLi / XSS / RCE
      SSRF / LFI / RFI
      SSTI / XXE / WebShell
      Bot & Scanner
    Kiểm soát lưu lượng
      Giới hạn tần suất
      Chống DDoS / CC
      Phát hiện gian lận giao dịch
    Trí thông minh
      Chấm điểm rủi ro
      Vân tay thiết bị
      Tình báo CrowdSec
      Chặn theo quốc gia
    Vận hành
      Trang quản trị web
      Đa máy chủ (Cluster)
      Nạp nóng quy tắc
      Cảnh báo thời gian thực
```

**Năng lực chính:**

- **Đa giao thức:** Hỗ trợ HTTP/1.1, HTTP/2 và HTTP/3 (QUIC) — *tự động chọn phiên bản nhanh nhất mà trình duyệt hỗ trợ*.
- **Dây chuyền kiểm tra nhiều lớp:** Mỗi request đi qua một loạt trạm kiểm soát (xem [Mục 5](#5-dây-chuyền-kiểm-tra-an-ninh-pipeline)).
- **Hơn 650 quy tắc dựng sẵn:** Gồm bộ chuẩn OWASP, các bản vá lỗ hổng CVE, quy tắc nâng cao, nhận diện bot, ModSecurity và OWASP API Security.
- **Quy tắc tuỳ chỉnh:** Tự viết luật riêng bằng giao diện kéo-thả, định dạng YAML, hoặc kịch bản **Rhai**.
- **Chấm điểm rủi ro tích luỹ:** Cộng dồn nhiều tín hiệu nghi ngờ để ra quyết định thông minh thay vì chỉ "có/không".
- **Vân tay thiết bị (JA3/JA4):** Nhận ra cùng một công cụ tấn công kể cả khi nó đổi địa chỉ IP.
- **Trang quản trị React:** Đăng nhập bằng **JWT**, hỗ trợ **đa ngôn ngữ** (Tiếng Anh, Tiếng Việt, Tiếng Trung), giám sát theo thời gian thực qua WebSocket.
- **Lưu trữ PostgreSQL:** Toàn bộ cấu hình, log, quy tắc được lưu trong cơ sở dữ liệu, giá trị nhạy cảm được **mã hoá AES-256-GCM**.
- **Phân cụm tuỳ chọn:** Chạy nhiều máy qua **QUIC + mTLS**, tự bầu máy chỉ huy, đồng bộ quy tắc nén lz4.

### 1.2 Một vài con số

| Chỉ số | Giá trị |
|--------|---------|
| Phiên bản | **1.1.0** |
| Ngôn ngữ | Rust (ấn bản 2024) |
| Nền proxy | Cloudflare Pingora |
| Số crate (mô-đun) | **7** |
| Tổng quy tắc dựng sẵn | **hơn 650** |
| Giao thức | HTTP/1.1, HTTP/2, HTTP/3 |
| Ngôn ngữ giao diện | 3 (en, vi, zh) |

---

## 2. Kiến Trúc Hệ Thống

### 2.1 Bảy mô-đun (crate) ghép thành WAF

Hãy hình dung F&G WAF như **một chiếc xe hơi gồm nhiều bộ phận**. Mỗi "crate" *(mô-đun mã nguồn)* đảm nhiệm một việc:

| Crate (bộ phận) | Ví như | Nhiệm vụ |
|---|---|---|
| **`prx-waf`** | Chìa khoá & bảng điều khiển | File chạy chính (`waf`): khởi động hệ thống, xử lý các lệnh dòng lệnh (CLI) |
| **`gateway`** | Cửa xe & khung gầm | Proxy dựa trên Pingora: nhận kết nối, giải mã TLS, hỗ trợ HTTP/3, làm cache, chuyển tiếp vào máy chủ đích |
| **`waf-engine`** | Động cơ | "Bộ não" phát hiện tấn công: chạy mọi quy tắc, vân tay thiết bị, chấm điểm rủi ro, plugin (đây là crate *lớn nhất*) |
| **`waf-storage`** | Cốp chứa đồ | Lớp làm việc với cơ sở dữ liệu PostgreSQL, mã hoá dữ liệu nhạy cảm |
| **`waf-api`** | Bảng đồng hồ & nút bấm | API quản trị (Axum) + WebSocket + nhúng sẵn trang quản trị React |
| **`waf-common`** | Ốc vít & chi tiết chung | Các kiểu dữ liệu dùng chung: cấu hình, ngữ cảnh request, hành động |
| **`waf-cluster`** | Bộ đàm liên xe | Liên lạc giữa các máy trong cụm: QUIC mTLS, bầu chỉ huy (Raft), đồng bộ quy tắc |

```mermaid
graph TB
    subgraph CHAY["File chạy duy nhất: waf"]
        PRX["prx-waf<br/><i>khởi động + dòng lệnh</i>"]
        GW["gateway<br/><i>proxy Pingora · TLS · HTTP/3 · cache</i>"]
        ENG["waf-engine<br/><i>bộ não phát hiện tấn công</i>"]
        API["waf-api<br/><i>API quản trị + WebSocket + UI</i>"]
        CLU["waf-cluster<br/><i>liên lạc đa máy</i>"]
        STO["waf-storage<br/><i>cơ sở dữ liệu</i>"]
        COM["waf-common<br/><i>kiểu dùng chung</i>"]
    end
    DB[("PostgreSQL<br/>cấu hình · log · quy tắc")]
    BK["Máy chủ website<br/>(backend)"]

    PRX --> GW & API & CLU
    GW --> ENG
    API --> STO --> DB
    ENG --> STO
    GW --> BK
    API -. cập nhật quy tắc .-> ENG
    CLU --> STO
```

### 2.2 Một request đi qua hệ thống như thế nào?

```mermaid
flowchart LR
    C([👤 Người dùng]) -->|"1.kết nối<br/>TCP/TLS/QUIC"| GW[gateway<br/>nhận & giải mã]
    GW -->|"2.hỏi: an toàn không?"| ENG[waf-engine<br/>chạy dây chuyền kiểm tra]
    ENG -->|"3a.✅ an toàn"| CACHE{có trong<br/>cache?}
    ENG -->|"3b.🚫 nguy hiểm"| BLOCK([Trả về 403<br/>+ ghi log])
    CACHE -->|có| FAST([Trả lời ngay<br/>từ cache])
    CACHE -->|không| BK([Máy chủ website])
    BK -->|phản hồi| C
```

**Diễn giải từng bước:**
1. Người dùng kết nối tới WAF (qua HTTP, HTTPS hoặc HTTP/3). `gateway` nhận và *giải mã* lớp bảo mật TLS để đọc được nội dung.
2. `gateway` đưa request cho `waf-engine` hỏi: "request này có an toàn không?".
3. `waf-engine` chạy toàn bộ [dây chuyền kiểm tra](#5-dây-chuyền-kiểm-tra-an-ninh-pipeline) rồi trả về một trong các quyết định: **Cho qua**, **Chặn (403)**, hoặc **Thách thức**.
4. Nếu cho qua: kiểm tra **cache** — nếu đã có câu trả lời sẵn thì trả lời ngay (rất nhanh); nếu chưa, chuyển vào máy chủ website thật rồi trả kết quả về.

### 2.3 Bốn tầng ưu tiên (Tier) — FR-002

Không phải đường dẫn nào cũng quan trọng như nhau. Trang `/login` (đăng nhập) cần bảo vệ ngặt nghèo hơn trang `/anh-nen.jpg`. Vì vậy WAF **phân loại mỗi request vào một trong 4 tầng** *trước khi* kiểm tra, và mỗi tầng có chính sách riêng:

```mermaid
flowchart TD
    R([Request đến]) --> CLS{Bộ phân loại Tier}
    CLS -->|"/login, thanh toán"| CR["🔴 CRITICAL<br/>chặn-khi-lỗi · ngưỡng thấp · không cache"]
    CLS -->|"/api/*"| HI["🟠 HIGH<br/>chặn-khi-lỗi · cache ngắn"]
    CLS -->|"trang người dùng"| ME["🟡 MEDIUM<br/>cho-qua-khi-lỗi · cache mặc định"]
    CLS -->|"còn lại"| CA["🟢 CATCHALL<br/>cho-qua-khi-lỗi · cache mạnh"]
```

| Tầng | Lưu lượng điển hình | Khi WAF gặp lỗi | Mức chống DDoS | Cache |
|------|---------------------|-----------------|----------------|-------|
| **🔴 Critical** | Đăng nhập, thanh toán, xác thực | **Chặn** (fail-close — ưu tiên an toàn) | Rất nghiêm (≈50 req/giây) | Không cache |
| **🟠 High** | API, dịch vụ nội bộ | **Chặn** (fail-close) | Nghiêm (≈200 req/giây) | Cache ngắn |
| **🟡 Medium** | Trang người dùng đã đăng nhập | **Cho qua** (fail-open — ưu tiên không gián đoạn) | Vừa (≈1.000 req/giây) | Cache mặc định |
| **🟢 CatchAll** | Mọi thứ còn lại (ảnh, tài nguyên tĩnh) | **Cho qua** (fail-open) | Lỏng | Cache mạnh |

> 💡 **Vì sao quan trọng:** Trang đăng nhập chọn "chặn-khi-lỗi" — thà chặn nhầm còn hơn để lọt kẻ gian vào nơi nhạy cảm. Ngược lại, ảnh nền chọn "cho-qua-khi-lỗi" — không đáng để website hiển thị vỡ chỉ vì một trục trặc nhỏ.

---

## 3. Cài Đặt & Triển Khai

Có 3 cách chạy F&G WAF, từ dễ tới nâng cao.

### 3.1 Cách nhanh nhất — Docker Compose (khuyến nghị cho người mới)

**Yêu cầu:** Đã cài Docker, máy có khoảng 4 GB RAM, và các cổng `16880`, `16843`, `16827` còn trống.

```bash
# Tải mã nguồn về
git clone https://github.com/future-and-go/mini-waf
cd mini-waf

# Khởi động toàn bộ (WAF + cơ sở dữ liệu + cache) chỉ bằng 1 lệnh
docker compose up -d

# Kiểm tra "sức khoẻ" hệ thống (-k vì admin dùng HTTPS chứng chỉ tự ký)
curl -k https://localhost:16827/health
```

Sau đó mở trình duyệt vào **trang quản trị**: `https://localhost:16827/ui/`

**Bảng cổng (Docker):**

| Cổng trên máy bạn | Cổng bên trong | Dùng để |
|-------------------|----------------|---------|
| `16880` | `80` | Nhận lưu lượng HTTP của khách |
| `16843` | `443` | Nhận lưu lượng HTTPS của khách |
| `16827` | `9527` | Trang quản trị + API (chạy qua HTTPS) |
| `15432` | `5432` | PostgreSQL (tuỳ chọn, để truy cập trực tiếp DB) |

> 🔐 **Mật khẩu quản trị lần đầu — đọc kỹ:** Tài khoản mặc định là `admin`. **Mật khẩu KHÔNG cố định.** Khi chạy lần đầu, WAF sẽ:
> - Lấy mật khẩu từ biến môi trường **`ADMIN_PASSWORD`** nếu bạn đặt sẵn, **hoặc**
> - **Tự sinh một mật khẩu ngẫu nhiên** và *in ra nhật ký (log)* khi khởi động.
>
> 👉 Cách an toàn nhất: đặt `ADMIN_PASSWORD` trước khi khởi động. Nếu không, hãy xem log để lấy mật khẩu:
> ```bash
> docker compose logs prx-waf | grep -i password
> ```
> **Đổi mật khẩu ngay sau khi đăng nhập lần đầu.**

### 3.2 Cách thủ công — Tự build (cho người rành kỹ thuật)

**Yêu cầu:** Rust 1.86 trở lên, PostgreSQL 16+, Node.js 22+ (để build trang quản trị).

```bash
# 1. Build giao diện quản trị (sẽ được nhúng thẳng vào file chạy)
cd web/admin-panel && npm ci && npm run build && cd ../..

# 2. Build file chạy WAF (bản tối ưu)
cargo build --release

# 3. Tạo cơ sở dữ liệu
createdb waf
createuser waf

# 4. Nạp cấu trúc bảng vào DB
./target/release/waf -c configs/default.toml migrate

# 5. Tạo tài khoản quản trị (đặt mật khẩu qua biến môi trường)
ADMIN_PASSWORD='mat-khau-manh-cua-ban' ./target/release/waf -c configs/default.toml seed-admin

# 6. Khởi động
./target/release/waf -c configs/default.toml run
```

Kiểm tra: `curl -k https://127.0.0.1:9527/health`

### 3.3 Chạy như dịch vụ hệ thống (systemd) — cho máy chủ thật

Cách này giúp WAF **tự khởi động khi bật máy** và **tự hồi phục khi gặp sự cố**.

```bash
# Cài file chạy vào hệ thống
sudo install -m 0755 target/release/waf /usr/local/bin/waf
sudo useradd -r -s /sbin/nologin waf
sudo mkdir -p /etc/waf /var/lib/waf /var/log/waf
sudo install -m 0640 -o waf configs/default.toml /etc/waf/config.toml
```

Tạo file `/etc/systemd/system/waf.service`:

```ini
[Unit]
Description=F&G WAF — Reverse Proxy và Tường Lửa Ứng Dụng Web
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
Type=simple
User=waf
ExecStart=/usr/local/bin/waf -c /etc/waf/config.toml run
Restart=on-failure
RestartSec=10s
# Cho phép mở cổng 80/443 dù không chạy bằng root
AmbientCapabilities=CAP_NET_BIND_SERVICE
LimitNOFILE=65535
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now waf      # bật + chạy ngay
sudo systemctl status waf            # xem trạng thái
journalctl -u waf -f                 # xem log trực tiếp
```

---

## 4. Hướng Dẫn Sử Dụng Trang Quản Trị (Admin UI)

Trang quản trị là một ứng dụng web (viết bằng **React + Refine + Ant Design**) phục vụ tại `https://<máy-chủ>:16827/ui/`. Mọi số liệu cập nhật **theo thời gian thực** nhờ kết nối WebSocket. Đăng nhập bằng tài khoản + mật khẩu (cấp **JWT** — "vé thông hành" hiệu lực 24 giờ).

### Bản đồ các trang trong giao diện

```mermaid
flowchart TD
    Login[🔑 Đăng nhập] --> Dash[📊 Dashboard]
    Dash --> G1
    subgraph G1["Vận hành cơ bản"]
        Hosts[Hosts]
        IPR[IP Rules]
        URLR[URL Rules]
        SSL[SSL Certificates]
        CC[CC Protection]
        Noti[Notifications]
        Set[Settings]
    end
    subgraph G2["Theo dõi & điều tra"]
        SE[Security Events]
        SL[Security Logs]
        RA[Rule Analytics]
        Cache[Cache Dashboard]
    end
    subgraph G3["Quản lý quy tắc"]
        RM[Rule Manager]
        CR[Custom Rules]
        RS[Rule Sources]
        BM[Bot Management]
        SP[Sensitive Patterns]
    end
    subgraph G4["Phòng thủ nâng cao"]
        DDoS[DDoS Protection]
        Risk[Risk Scoring]
        Chal[Challenge Engine]
        DFP[Device Fingerprinting]
        Relay[Relay Intel]
        Geo[Geo Restriction]
        Tier[Tier Policies]
        TX[TX Velocity]
        CS[CrowdSec]
    end
    Dash --> G2 & G3 & G4
```

> Giao diện hiện có **34 trang**. Dưới đây mô tả các trang chính kèm ảnh chụp màn hình; phần [4.20](#420-các-trang-phòng-thủ-nâng-cao) tóm tắt nhanh các trang nâng cao.

### 4.1 Đăng Nhập

![Trang đăng nhập](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_29_46.png)
*Hình 4.1 — Màn hình đăng nhập*

- Nhập **Tên đăng nhập** và **Mật khẩu**.
- Nếu đã bật **TOTP** (xác thực 2 lớp), nhập thêm mã OTP 6 số.
- Sau khi đăng nhập, hệ thống cấp **JWT** lưu trong trình duyệt; hết hạn sau 24 giờ thì tự đăng nhập lại.

### 4.2 Dashboard (Bảng điều khiển)

![Dashboard](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_30_23.png)
*Hình 4.2 — Bảng điều khiển tổng quan theo thời gian thực*

Đây là "phòng điều khiển trung tâm". Bạn nhìn một lượt là biết sức khoẻ an ninh của toàn hệ thống:

- **Thẻ số liệu:** Tổng request, số bị chặn, số cho qua, tỉ lệ chặn, số host đang chạy, số IP tấn công riêng biệt, số quy tắc đang hoạt động, số lần dính bẫy honeypot…
- **Biểu đồ:** Lưu lượng 24 giờ (hợp lệ xanh / bị chặn đỏ), phân loại tấn công, phân bố điểm rủi ro, bản đồ quốc gia tấn công, top IP tấn công, top quy tắc bị kích hoạt…
- **Luồng sự kiện trực tiếp:** Danh sách các vụ chặn mới nhất tự "nhảy" lên theo thời gian thực.
- **Bộ lọc:** Theo host, theo hành động, theo khung thời gian (1h/6h/24h/7 ngày).

### 4.3 Hosts (Khai báo website cần bảo vệ)

![Trang Hosts](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_30_42.png)
*Hình 4.3 — Quản lý các website (host) được proxy*

Mỗi "host" là **một website bạn muốn WAF đứng ra bảo vệ**. Bạn khai báo: tên miền nào → trỏ về máy chủ thật nào.

| Trường | Ý nghĩa | Ví dụ |
|--------|---------|-------|
| Host | Tên miền cần bảo vệ | `api.example.com` |
| Port | Cổng WAF lắng nghe | `80` |
| Upstream | Địa chỉ máy chủ thật (đằng sau) | `127.0.0.1` |
| Upstream Port | Cổng máy chủ thật | `8080` |
| SSL | Bật giải mã HTTPS cho host này | bật/tắt |
| Guard | Bật kiểm tra WAF | bật (mặc định) |
| Start | Kích hoạt host này | bật |
| Log only | Chỉ ghi log, không chặn (để thử nghiệm) | tắt |

> ⚡ **Nạp nóng:** Thêm/sửa host có hiệu lực *ngay*, không cần khởi động lại.

### 4.4 IP Rules (Danh sách IP trắng/đen)

![Trang IP Rules](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_31_06.png)
*Hình 4.4 — Danh sách IP cho phép (trái) và chặn (phải)*

- **Allow List** (danh sách trắng): IP/dải IP được tin tưởng, bỏ qua kiểm tra.
- **Block List** (danh sách đen): IP/dải IP bị chặn ngay với mã lỗi 403.

Hỗ trợ cả IP đơn (`192.168.1.5`) và dải **CIDR** (`10.0.0.0/8`, `2001:db8::/32`).

### 4.5 URL Rules (Danh sách đường dẫn trắng/đen)

![Trang URL Rules](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_31_23.png)
*Hình 4.5 — Danh sách URL cho phép (trái) và chặn (phải)*

- **Allow URLs:** đường dẫn được *bỏ qua toàn bộ* kiểm tra WAF (dùng cẩn thận!).
- **Block URLs:** đường dẫn bị chặn ngay.

Hỗ trợ: khớp chính xác (`/health`), biểu thức **regex** (`^/admin/.*`), và ký tự đại diện (`/static/*`).

### 4.6 Security Events (Nhật ký tấn công)

![Trang Security Events](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_31_37.png)
*Hình 4.6 — Nhật ký các vụ tấn công đã chặn*

Đây là **sổ ghi các vụ tấn công**. Mỗi dòng cho biết: thời gian, IP nguồn, phương thức (GET/POST), đường dẫn, quy tắc nào bị kích hoạt, mã quy tắc (vd `SSRF-006`), và hành động (chặn/cho qua/thách thức).

Bấm vào một sự kiện để xem **chi tiết**:

![Chi tiết Security Event](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_34_04.png)
*Hình 4.6b — Chi tiết một vụ tấn công, gồm cả "payload" thực tế*

Và có nút **"Tạo quy tắc tuỳ chỉnh từ sự kiện này"** — tự điền sẵn thông tin để bạn nhanh chóng lập luật chặn kẻ tấn công đó:

![Tạo Custom Rule từ sự kiện](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_34_17.png)
*Hình 4.6c — Tự động tạo quy tắc chặn từ một vụ tấn công*

### 4.7 Security Logs (Nhật ký truy cập đầy đủ)

![Trang Security Logs](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_31_57.png)
*Hình 4.7 — Nhật ký *tất cả* request (cả cho qua lẫn bị chặn)*

Khác với Security Events (chỉ ghi vụ tấn công), trang này ghi **mọi request**. Có bộ lọc nâng cao và xuất file CSV để phân tích.

### 4.8 SSL Certificates (Chứng chỉ HTTPS)

![Trang SSL Certificates](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_32_08.png)
*Hình 4.8 — Quản lý chứng chỉ TLS*

Quản lý "giấy chứng minh thư" HTTPS cho các website:
- **Tải lên thủ công:** dán chứng chỉ và khoá riêng (định dạng PEM).
- **Let's Encrypt tự động:** WAF tự xin chứng chỉ miễn phí và **tự gia hạn 30 ngày trước khi hết hạn**.

### 4.9 CC Protection & Cân Bằng Tải

![Trang CC Protection](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_32_26.png)
*Hình 4.9 — Chống tấn công CC + chống "hotlink" + cân bằng tải*

- **Cân bằng tải (Load Balancer):** thêm nhiều máy chủ đích, WAF chia đều lưu lượng theo trọng số.
- **Chống Hotlink:** chặn website khác "nhúng trộm" ảnh/video của bạn (kiểm tra header `Referer`).

### 4.10 Notifications (Cảnh báo)

![Trang Notifications](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_32_40.png)
*Hình 4.10 — Cấu hình kênh nhận cảnh báo*

Khi có sự kiện an ninh, WAF có thể tự gửi cảnh báo qua **Webhook, Email hoặc Telegram**. Ví dụ cấu hình Telegram:
```json
{ "bot_token": "123456:ABC-DEF", "chat_id": "-100123456789" }
```

### 4.11 Settings (Cài đặt hệ thống)

![Trang Settings](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_32_55.png)
*Hình 4.11 — Bảng cài đặt vận hành WAF*

Trang này điều khiển hành vi của "bộ não" WAF, gồm các nhóm quan trọng:
- **Shadow Mode (chế độ bóng):** bật để *thử nghiệm an toàn* — tính quyết định nhưng không thực thi.
- **Ngưỡng rủi ro:** thanh trượt đặt mốc Cho qua / Thách thức / Chặn.
- **Honeypot Paths:** các đường dẫn bẫy (mặc định gồm `/.git/config`, `/.aws/credentials`…).
- **Lọc phản hồi:** chặn lộ "vết lỗi" (stack trace) và che các trường nhạy cảm như `password`, `token`.
- **Trusted IPs:** danh sách IP luôn được tin tưởng (mặc định gồm `127.0.0.1`).
- **Auto-block:** tự chặn IP khi có quá nhiều sự kiện trong khoảng thời gian ngắn.

### 4.12 Rule Manager (Quản lý quy tắc)

![Trang Rule Management](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_33_06.png)
*Hình 4.12 — Toàn bộ quy tắc dựng sẵn*

Xem **toàn bộ hơn 650 quy tắc** với mã, tên, danh mục, nguồn, mức nghiêm trọng, hành động, và công tắc bật/tắt từng quy tắc. Có ô tìm kiếm và bộ lọc.

![Dialog Import Rules](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_33_33.png)
*Hình 4.12b — Nhập quy tắc từ file hoặc URL*

### 4.13 Custom Rules (Quy tắc tự định nghĩa)

![Trang Custom Rules](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_33_48.png)
*Hình 4.13 — Tạo quy tắc riêng của bạn*

Tự viết luật riêng bằng **giao diện kéo-thả** (chế độ Visual), bằng **JSON**, hoặc bằng kịch bản **Rhai**. Bạn có thể kết hợp nhiều điều kiện theo logic **VÀ / HOẶC / KHÔNG** (xem chi tiết cú pháp ở [Mục 6.8](#68-quy-tắc-tuỳ-chỉnh-trong-cơ-sở-dữ-liệu)).

### 4.14 Rule Sources (Nguồn quy tắc)

![Trang Rule Sources](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_34_31.png)
*Hình 4.14 — Các nguồn quy tắc dựng sẵn và thêm nguồn từ xa*

Ngoài các nguồn dựng sẵn (owasp-crs, advanced, cve-patches…), bạn có thể thêm **nguồn quy tắc từ xa** qua URL và đặt lịch tự đồng bộ (ví dụ mỗi 24 giờ) để luôn có bản vá mới nhất.

### 4.15 Rule Analytics (Phân tích quy tắc)

![Trang Rule Analytics](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_34_43.png)
*Hình 4.15 — Thống kê tấn công theo nhóm quy tắc và đường dẫn*

Biểu đồ cho biết nhóm quy tắc nào "bắt" được nhiều tấn công nhất, đường dẫn nào bị nhắm tới nhiều nhất — giúp bạn hiểu mình đang bị tấn công kiểu gì.

### 4.16 Bot Management (Quản lý bot)

![Trang Bot Management](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_34_52.png)
*Hình 4.16 — Phân loại bot theo nhóm*

Phân loại bot thành các tab: **Bot tốt** (Googlebot, Bingbot… → cho qua), **Bot xấu** (Scrapy, công cụ cào → chặn), **AI Crawlers** (GPTBot, Claude-Web…), **Công cụ SEO** (Ahrefs, Semrush). Có công cụ **Test User-Agent** để thử một chuỗi nhận diện bất kỳ.

![Dialog Add Bot Pattern](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_34_59.png)
*Hình 4.16b — Thêm mẫu nhận diện bot bằng regex*

### 4.17 CrowdSec (Tình báo an ninh cộng đồng)

![CrowdSec Settings](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_35_43.png)
*Hình 4.17a — Cấu hình CrowdSec*

![CrowdSec Decisions](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_35_58.png)
*Hình 4.17b — Danh sách IP bị cộng đồng đánh dấu*

![CrowdSec Statistics](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_36_08.png)
*Hình 4.17c — Thống kê hiệu suất CrowdSec*

**CrowdSec** cho phép WAF dùng *danh sách IP xấu do cộng đồng toàn cầu chia sẻ*. Bạn nhập địa chỉ máy chủ CrowdSec (LAPI URL) và khoá API; WAF sẽ định kỳ tải về các "quyết định" (ban/captcha) và áp dụng.

### 4.18 Cache Dashboard (Bộ nhớ đệm)

![Cache Dashboard](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_36_17.png)
*Hình 4.18 — Hiệu suất bộ nhớ đệm theo thời gian thực*

Theo dõi tỉ lệ "trúng cache" (hit ratio), số mục đang lưu, bộ nhớ dùng, và các thao tác: **Xoá theo tag**, **Xoá theo route**, **Xoá toàn bộ**.

### 4.19 TX Velocity (Phát hiện gian lận giao dịch)

![Trang TX Velocity](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_36_26.png)
*Hình 4.19 — Phát hiện mẫu gian lận tài chính đa bước*

Dành cho các hệ thống tài chính (fintech): phát hiện các *mẫu hành vi đáng ngờ* trải trên nhiều bước, ví dụ:
- **Chuỗi quá nhanh:** Đăng nhập → OTP → Nạp tiền xong trong dưới 1,5 giây (giống bot, không giống người thật).
- **Rút tiền dồn dập:** ≥ 5 lần rút trong 60 giây.
- **Đổi hạn mức liên tục:** ≥ 3 lần đổi giới hạn trong 5 phút.

### 4.20 Các trang phòng thủ nâng cao

Ngoài các trang trên, giao diện còn có những trang chuyên sâu (tương ứng các tính năng FR ở [Phụ lục A](#phụ-lục-a-bản-đồ-tính-năng-fr)):

| Trang | Dùng để |
|-------|---------|
| **DDoS Protection** | Xem/chỉnh ngưỡng chống DDoS theo IP/vân tay/tầng, xem bảng IP đang bị cấm tạm |
| **Risk Scoring** | Theo dõi điểm rủi ro, các "diễn viên" (IP) rủi ro cao nhất, chỉnh dải ngưỡng |
| **Challenge Engine** | Cấu hình "câu đố" (proof-of-work/CAPTCHA) gửi cho khách đáng ngờ |
| **Device Fingerprinting** | Xem vân tay thiết bị (JA3/JA4), các tín hiệu bất thường |
| **Relay Intel** | Phân tích chuỗi proxy (header `X-Forwarded-For`), nhận diện Tor/trung tâm dữ liệu |
| **Geo Restriction** | Chặn/cho phép theo quốc gia (dựa trên GeoIP) |
| **Tier Policies** | Tinh chỉnh chính sách cho 4 tầng ưu tiên (fail-mode, ngưỡng, cache) |
| **Sensitive Patterns** | Khai báo từ khoá/định dạng dữ liệu nhạy cảm cần phát hiện & che |
| **Response Filtering** | Lọc nội dung phản hồi để tránh lộ thông tin nhạy cảm |
| **Plugins** | Bật/tắt các plugin tuỳ chỉnh (WASM) |
| **Tunnels** | Quản lý đường hầm kết nối tới máy chủ đích |

---

## 5. Dây Chuyền Kiểm Tra An Ninh (Pipeline)

### 5.1 Ý tưởng: nhiều trạm kiểm soát nối tiếp

Mỗi request được đưa qua **một dây chuyền nhiều trạm kiểm soát** — giống hành lý ở sân bay đi qua lần lượt: soi chiếu → cân nặng → kiểm tra chất lỏng… Tại bất kỳ trạm nào, nếu phát hiện vấn đề nghiêm trọng, request có thể **bị chặn ngay** mà không cần đi tiếp.

> 🧭 **Cách đọc sơ đồ dưới đây:** đi từ trên xuống. Các trạm "cổng vào" (chặn nhanh) nằm trước để loại bỏ kẻ xấu rõ ràng ngay lập tức, tiết kiệm công sức cho các trạm phân tích sâu phía sau.

```mermaid
flowchart TD
    START([Request đến]) --> PRE

    subgraph PRE["🔍 Tiền xử lý: nhận diện danh tính"]
        FR007["Phân tích chuỗi proxy (FR-007)<br/>X-Forwarded-For · ASN · Tor"]
        FR010["Vân tay thiết bị (FR-010)<br/>JA3/JA4 · HTTP/2"]
        FR007 --> FR010
    end

    PRE --> GATE
    subgraph GATE["🚪 Cổng vào: chặn/cho qua nhanh"]
        IPW["Danh sách IP trắng"] --> IPB["Danh sách IP đen"]
        IPB --> URLW["Danh sách URL trắng → bỏ qua hết"]
        URLW --> URLB["Danh sách URL đen"]
    end

    GATE --> REP
    subgraph REP["🌐 Danh tiếng & lưu lượng"]
        DDOS["Chống DDoS (FR-005)<br/>theo IP/vân tay/tầng"]
        CSB["CrowdSec (cache quyết định)"]
        COMM["Danh sách chặn cộng đồng"]
        GEOIP["Chặn theo quốc gia (GeoIP)"]
        RL["Giới hạn tần suất (FR-004)<br/>token-bucket + cửa sổ trượt"]
        DDOS --> CSB --> COMM --> GEOIP --> RL
    end

    REP --> ATK
    subgraph ATK["⚔️ Phát hiện tấn công"]
        TX["Gian lận giao dịch (FR-012)"]
        SCAN["Scanner (Nikto/Nmap/sqlmap...)"]
        BOT["Bot xấu / headless"]
        SQLI["SQL Injection<br/>libinjection + regex"]
        XSS["XSS"]
        RCE["RCE / chèn lệnh"]
        TRAV["Đi lạc thư mục + SSRF"]
        HINJ["Chèn header / body bất thường"]
        TX --> SCAN --> BOT --> SQLI --> XSS --> RCE --> TRAV --> HINJ
    end

    ATK --> RULES
    subgraph RULES["📜 Bộ máy quy tắc"]
        CUSTOM["Quy tắc tuỳ chỉnh (FR-003)<br/>cây VÀ/HOẶC/KHÔNG + Rhai"]
        OWASP["OWASP CRS (vài trăm quy tắc)"]
        SENS["Quét dữ liệu nhạy cảm<br/>Aho-Corasick"]
        HOTLINK["Chống hotlink (Referer)"]
        CUSTOM --> OWASP --> SENS --> HOTLINK
    end

    RULES --> SCORE
    subgraph SCORE["🧮 Chấm điểm & quyết định (FR-025)"]
        RISK["Cộng dồn điểm rủi ro<br/>L0 + L1 + L2"]
    end

    SCORE --> DECIDE{Điểm so với ngưỡng?}
    DECIDE -->|thấp| ALLOW([✅ Cho qua → cache → máy chủ])
    DECIDE -->|trung bình| CHAL([🧩 Thách thức: câu đố/CAPTCHA])
    DECIDE -->|cao| BLOCK([🚫 Chặn 403 + ghi log])
```

> ⚙️ **Lưu ý kỹ thuật (cho người rành):** Thứ tự thực thi *thực tế* trong mã nguồn được sắp xếp để chặn nhanh nhất các mối đe doạ rõ ràng (IP/URL đen, DDoS, CrowdSec, GeoIP) *trước*, rồi mới tới các bộ phát hiện tấn công tốn công hơn (SQLi, XSS, RCE…), cuối cùng là quy tắc tuỳ chỉnh và OWASP CRS, và sau chót là tổng hợp điểm rủi ro để ra quyết định. Sơ đồ trên phản ánh đúng nhóm và thứ tự đó (đã được kiểm chứng với mã nguồn `waf-engine`).

### 5.2 Các quyết định có thể xảy ra

```mermaid
flowchart LR
    Q[Sau khi qua dây chuyền] --> A{Quyết định}
    A -->|Allow| AA["✅ Cho qua<br/>request tới máy chủ"]
    A -->|Challenge| CC["🧩 Thách thức<br/>bắt giải câu đố trước"]
    A -->|Block| BB["🚫 Chặn (403)<br/>+ ghi vào Security Events"]
    A -->|Log only| LL["📓 Chỉ ghi log<br/>(chế độ bóng/thử nghiệm)"]
```

### 5.3 Cách chấm điểm rủi ro (FR-025) — giải thích dễ hiểu

Thay vì chỉ phán "tốt/xấu" cho từng dấu hiệu, WAF **cộng dồn điểm nghi ngờ**. Mỗi dấu hiệu xấu cộng thêm một số điểm; khi tổng điểm vượt ngưỡng, WAF hành động.

```mermaid
flowchart TD
    L0["L0 — Lớp hạt giống<br/>danh sách tin cậy (IP/ASN)<br/><i>tắt theo mặc định</i>"]
    L1["L1 — Lớp tích luỹ<br/>điểm cộng từ các quy tắc khớp"]
    L2["L2 — Lớp hành vi & vận tốc<br/>vân tay lệch · chuỗi XFF lạ<br/>tần suất bất thường · bẫy honeypot"]
    L0 --> SUM(("Tổng điểm<br/>rủi ro"))
    L1 --> SUM
    L2 --> SUM
    SUM --> T{So ngưỡng theo tầng}
    T -->|≤ allow| OK[Cho qua]
    T -->|allow→challenge| CH[Thách thức]
    T -->|> block| BL[Chặn]
```

- **L0 (hạt giống):** Cho điểm khởi đầu dựa trên danh sách tin cậy. *Mặc định tắt.*
- **L1 (tích luỹ):** Mỗi quy tắc khớp đóng góp một lượng điểm (`risk_delta`).
- **L2 (hành vi/vận tốc):** Cộng điểm khi phát hiện bất thường — ví dụ vân tay thiết bị không khớp trình duyệt khai báo, chuỗi proxy giả mạo, tần suất gõ cửa đều như máy, hoặc chạm vào bẫy honeypot (trường hợp này điểm bị đẩy lên kịch trần để chặn chắc chắn).
- **Ngưỡng theo tầng:** Mỗi tầng (Critical/High/…) có 3 mốc `allow / challenge / block` riêng. Trang quan trọng đặt mốc thấp (nhạy hơn).

### 5.4 Bảng tóm tắt các trạm kiểm soát

| Nhóm | Trạm | Mã FR | Cơ chế | Khi nào chặn |
|------|------|-------|--------|--------------|
| Tiền xử lý | Phân tích proxy | FR-007 | Đọc `X-Forwarded-For`, phân loại ASN/Tor | (chỉ gắn nhãn, cộng điểm) |
| Tiền xử lý | Vân tay thiết bị | FR-010 | JA3/JA4 + HTTP/2 | (chỉ gắn nhãn, cộng điểm) |
| Cổng vào | IP trắng/đen | — | Tra dải CIDR (cây Patricia) | IP nằm trong danh sách đen |
| Cổng vào | URL trắng/đen | — | Khớp đường dẫn (literal/regex) | URL nằm trong danh sách đen |
| Lưu lượng | Chống DDoS | FR-005 | Cửa sổ trượt theo IP/vân tay/tầng | Vượt ngưỡng → cấm tạm |
| Lưu lượng | Giới hạn tần suất | FR-004 | Token-bucket + cửa sổ trượt | Vượt giới hạn IP/phiên |
| Danh tiếng | CrowdSec | — | Tra cache quyết định từ LAPI | IP có quyết định ban |
| Danh tiếng | Cộng đồng / GeoIP | FR-017/018 | Danh sách chặn / quốc gia | IP/quốc gia bị chặn |
| Tấn công | Scanner | — | Vân tay User-Agent | Khớp chữ ký công cụ dò |
| Tấn công | Bot | — | Phân tích User-Agent | Khớp bot xấu |
| Tấn công | SQLi | — | libinjection + regex (giải mã URL 3 vòng) | Phát hiện payload SQLi |
| Tấn công | XSS | — | Bộ regex (~16 mẫu) | Phát hiện payload XSS |
| Tấn công | RCE | — | Bộ regex (~20 mẫu) | Phát hiện lệnh shell/EL |
| Tấn công | Traversal/SSRF | FR-016 | Chuẩn hoá path + chặn dải nội bộ RFC1918 | Phát hiện `../` hoặc địa chỉ nội bộ |
| Quy tắc | Tuỳ chỉnh | FR-003 | Cây VÀ/HOẶC/KHÔNG + Rhai | Điều kiện khớp |
| Quy tắc | OWASP CRS | — | Vài trăm quy tắc đã biên dịch | Khớp quy tắc CRS |
| Quy tắc | Dữ liệu nhạy cảm | — | Aho-Corasick đa mẫu | Có từ khoá nhạy cảm |
| Quy tắc | Chống hotlink | — | Kiểm tra header Referer | Referer không hợp lệ |
| Quyết định | Chấm điểm rủi ro | FR-025 | Cộng dồn L0+L1+L2 | Điểm ≥ ngưỡng |

> 📌 Ngoài ra còn có các bộ kiểm tra **chèn header bất thường (Header Injection)**, **dò mật khẩu (Brute Force — đếm số lần 401/403)** và **lạm dụng thân request (Request Body Abuse — body quá lớn/lồng sâu)** chạy cùng nhóm phát hiện tấn công.

---

## 6. Danh Mục Quy Tắc Bảo Vệ

F&G WAF đi kèm **hơn 650 quy tắc dựng sẵn**, được tổ chức thành nhiều nguồn. Bạn không cần viết gì cũng đã được bảo vệ ngay.

> ℹ️ **Lưu ý về con số:** Số quy tắc *được định nghĩa* trong các file là hơn 650. Số quy tắc *đang bật* có thể ít hơn vì một số được tắt sẵn để giảm báo nhầm. Bảng dưới đây là số lượng theo từng nguồn (kiểm chứng từ thư mục `rules/`).

```mermaid
pie showData
    title Phân bổ quy tắc theo nguồn
    "OWASP CRS" : 368
    "Advanced (nâng cao)" : 77
    "OWASP API Security" : 64
    "ModSecurity" : 46
    "CVE Patches" : 43
    "Bot Detection" : 42
    "Custom (mẫu)" : 10
    "GeoIP" : 2
```

### 6.1 OWASP Core Rule Set (`rules/owasp-crs/`) — ~368 quy tắc

Bộ luật chuẩn quốc tế, là "xương sống" bảo vệ. Gồm các nhóm:

| Nhóm | Bảo vệ chống |
|------|--------------|
| `sqli.yaml` | SQL Injection |
| `xss.yaml` | Cross-Site Scripting |
| `lfi.yaml` / `rfi.yaml` | Đọc file nội bộ / tải file từ xa |
| `rce.yaml` | Chèn lệnh hệ điều hành |
| `php-injection.yaml` / `java-injection.yaml` | Chèn mã PHP / Java |
| `web-shells.yaml` | Upload/truy cập web shell |
| `protocol-enforcement.yaml` / `protocol-attack.yaml` | Vi phạm giao thức HTTP, request smuggling |
| `scanner-detection.yaml` | Chữ ký công cụ dò quét |
| `data-leakage*.yaml` / `response-*.yaml` | Phát hiện lộ dữ liệu/lỗi trong phản hồi |

### 6.2 Bản vá lỗ hổng CVE (`rules/cve-patches/`) — ~43 quy tắc

Chặn các lỗ hổng *nổi tiếng đã được công bố*:

| File | CVE | Mô tả |
|------|-----|-------|
| `2021-log4shell.yaml` | CVE-2021-44228… | **Log4Shell** — lỗ hổng JNDI chấn động 2021 |
| `2022-spring4shell.yaml` | CVE-2022-22965 | Khai thác Spring Framework |
| `2022-text4shell.yaml` | CVE-2022-42889 | Apache Commons Text RCE |
| `2023-moveit.yaml` | CVE-2023-34362 | MOVEit Transfer SQLi |
| `2024-xz-backdoor.yaml` | CVE-2024-3094 | Backdoor XZ Utils |
| `2024-recent.yaml` / `2025-recent.yaml` | nhiều CVE | Lỗ hổng nghiêm trọng mới |

### 6.3 Quy tắc nâng cao (`rules/advanced/`) — ~77 quy tắc

Bao gồm các tấn công tinh vi: **SSRF** (chặn dải IP nội bộ, loopback, IP metadata đám mây), **SSTI** (13 engine template: Jinja2, Twig, Freemarker, Velocity, Smarty…), **XXE**, **Deserialization**, **Prototype Pollution**, và **WebShell Upload**.

### 6.4 Bot Detection (`rules/bot-detection/`) — ~42 quy tắc
Nhận diện công cụ **credential stuffing** (SentryMBA, SilverBullet…), crawler/scraper trái phép.

### 6.5 OWASP API Security (`rules/owasp-api/`) — ~64 quy tắc
Bảo vệ API theo chuẩn OWASP API Top 10: xác thực hỏng, lộ dữ liệu thừa, injection, gán hàng loạt (mass assignment), lạm dụng tần suất.

### 6.6 ModSecurity (`rules/modsecurity/`) — ~46 quy tắc
Danh tiếng IP, chống DoS, phát hiện lộ dữ liệu, kiểm tra phản hồi bất thường.

### 6.7 GeoIP & Threat Intel
Chặn theo quốc gia (mã ISO) và danh sách seed ASN của các nhà cung cấp đám mây lớn (AWS, GCP, Azure, Cloudflare).

### 6.8 Quy tắc tuỳ chỉnh trong cơ sở dữ liệu

Bạn tự viết luật riêng, lưu trong DB, quản lý qua giao diện. Định dạng `custom_rule_v1`:

```yaml
kind: custom_rule_v1
id: CUSTOM-001
name: "Chặn admin từ IP không tin cậy"
enabled: true
priority: 100              # số nhỏ = ưu tiên cao hơn
host_code: "myapp"         # hoặc "*" cho mọi host
action: block              # block | allow | log | challenge
action_status: 403
risk_delta: 50             # cộng vào điểm rủi ro

# Cây điều kiện: kết hợp VÀ / HOẶC / KHÔNG
match_tree:
  and:
    - field: path
      operator: starts_with
      value: /admin/
    - not:
        field: ip
        operator: cidr_match
        value: 10.0.0.0/8

# Hoặc dùng kịch bản Rhai (nâng cao)
# script: |
#   ctx.path.starts_with("/api/") && ctx.method == "DELETE"
```

**Các trường (`field`) có thể kiểm tra:** `path`, `query`, `method`, `host`, `ip`, `user_agent`, `content_type`, `content_length`, `body`, `headers`, `cookie`, `response_body`, `geo_iso`, `geo_isp`, `all` (quét tất cả).

**Các toán tử (`operator`):** `eq` (bằng), `ne` (khác), `contains` (chứa), `not_contains`, `starts_with`, `ends_with`, `regex`, `wildcard`, `in_list`/`not_in_list`, `cidr_match` (khớp dải IP), `gt`/`lt`/`gte`/`lte` (so sánh số), `pm_from_file` (khớp đa từ khoá từ file), `contains_any`, `detect_sqli`, `detect_xss`, `validate_byte_range`.

---

## 7. Tham Chiếu Cấu Hình

Cấu hình chính nằm trong file **`configs/default.toml`** (định dạng TOML — dạng "khoá = giá trị" dễ đọc). Các cấu hình thay đổi thường xuyên (quy tắc, giới hạn tần suất…) tách ra file YAML riêng để **nạp nóng**.

### 7.1 File chính `configs/default.toml`

```toml
# ── Cổng nhận lưu lượng của khách ──
[proxy]
listen_addr     = "0.0.0.0:80"     # cổng HTTP
listen_addr_tls = "0.0.0.0:443"    # cổng HTTPS

# ── Trang quản trị + API (chạy HTTPS) ──
[api]
listen_addr = "0.0.0.0:9527"

# ── Cơ sở dữ liệu ──
[storage]
database_url    = "postgresql://waf:waf@postgres:5432/waf"
max_connections = 20

# ── Bộ nhớ đệm (FR-009) ──
[cache]
enabled          = true
backend          = "memory"    # memory | embedded | standalone | cluster
max_size_mb      = 256
default_ttl_secs = 60

# ── Chống DDoS (FR-005) ──
[ddos]
enabled = true

# ── Giới hạn tần suất (FR-004) — trỏ tới file YAML ──
[rate_limit]
config_path = "configs/rate-limit.yaml"

# ── Giới hạn an ninh ──
[security]
max_request_body_bytes = 10485760   # 10 MB
admin_ip_allowlist     = []         # CIDR được phép truy cập trang quản trị

# ── Một website được bảo vệ ──
[[hosts]]
host        = "example.com"
port        = 80
remote_host = "127.0.0.1"
remote_port = 8080
guard_status = true
```

**Các nhóm cấu hình khác** (có trong file mặc định): `[api.tls]` (chứng chỉ cho trang quản trị, tự sinh self-signed), `[http3]` (bật/tắt QUIC), `[panel]` (file cấu hình runtime `waf-panel.toml`), `[cluster]` (phân cụm), `[victoria_logs]` (lưu trữ nhật ký), `[community]` (tình báo cộng đồng), `[outbound]` (lọc rò rỉ trong phản hồi).

### 7.2 Các file cấu hình YAML (nạp nóng)

| File | Điều khiển |
|------|-----------|
| `configs/rate-limit.yaml` | Giới hạn tần suất theo từng tầng |
| `configs/ddos.yaml` | Ngưỡng chống DDoS theo IP/vân tay/tầng |
| `configs/challenge.yaml` | Cấu hình "câu đố" thách thức/CAPTCHA |
| `configs/device-fp.yaml` | Vân tay thiết bị (JA3/JA4) |
| `configs/tx-velocity.yaml` | Phát hiện gian lận giao dịch |
| `configs/tier-policies.yaml` | Chính sách 4 tầng ưu tiên |
| `configs/risk.yaml` | Dải điểm rủi ro và đường cong suy giảm |
| `configs/relay.yaml` | Nguồn tình báo proxy (ASN, Tor) |
| `configs/cache.yaml` | TTL cache theo từng route |
| `rules/access-lists.yaml` | Danh sách IP/host trắng-đen |

**Ví dụ giới hạn tần suất** (`configs/rate-limit.yaml`):
```yaml
version: 1
tiers:
  critical:
    ip:
      burst_capacity: 10         # cho phép "bùng" tối đa 10 request
      burst_refill_per_s: 5.0    # nạp lại 5 token/giây
      window_secs: 60
      window_limit: 100          # tối đa 100 request trong 60 giây
```

---

## 8. Phân Cụm & Khả Dụng Cao (Cluster/HA)

Khi một máy là chưa đủ (lưu lượng lớn, hoặc cần dự phòng để không bao giờ "sập"), bạn chạy **nhiều máy WAF cùng lúc**.

### 8.1 Cách hoạt động

```mermaid
graph TD
    subgraph MAIN["🧠 Node Chính (Main)"]
        DB[("PostgreSQL<br/>nguồn dữ liệu gốc")]
        REG["Kho quy tắc + nhật ký thay đổi"]
        ADMIN["Trang quản trị"]
        LEADER["Chỉ huy (Raft-lite)"]
    end
    subgraph WB["⚙️ Node Worker B"]
        C1["Bản sao quy tắc trong RAM"]
        P1["Proxy"]
    end
    subgraph WC["⚙️ Node Worker C"]
        C2["Bản sao quy tắc trong RAM"]
        P2["Proxy"]
    end

    MAIN -->|"đồng bộ quy tắc (nén lz4)<br/>QUIC + mTLS · cổng 16851"| WB
    MAIN -->|"đồng bộ quy tắc (nén lz4)<br/>QUIC + mTLS · cổng 16851"| WC
    WB -.->|"chuyển tiếp lệnh ghi"| MAIN
    WC -.->|"chuyển tiếp lệnh ghi"| MAIN
    LB[/"Bộ cân bằng tải"/] --> P1 & P2 & MAIN
```

**Nguyên tắc đơn giản:**
- **Node Main** giữ "bản gốc" dữ liệu (PostgreSQL) và là nơi quản trị.
- **Node Worker** chỉ giữ *bản sao quy tắc trong RAM* để xử lý cực nhanh; mọi *thay đổi* được chuyển về Main.
- Các node nói chuyện với nhau qua **QUIC + mTLS** (mã hoá hai chiều, chỉ máy được cấp giấy mới tham gia được), đồng bộ quy tắc **nén lz4**.
- Dùng thuật toán **Raft-lite** để bầu chỉ huy và giữ đồng nhất (cần đa số quá bán — vì vậy nên có **tối thiểu 3 node**).

### 8.2 Khởi động nhanh 3 node (Docker)

```bash
# 1. Tạo chứng chỉ cluster (chạy 1 lần)
podman-compose -f docker-compose.cluster.yml run --rm cluster-init

# 2. Khởi động 3 node
podman-compose -f docker-compose.cluster.yml up -d

# 3. Kiểm tra sức khoẻ từng node
curl -k https://localhost:16827/health    # node-a (main)
curl -k https://localhost:16828/health    # node-b (worker)
curl -k https://localhost:16829/health    # node-c (worker)

# 4. Xem trạng thái cụm
curl -k https://localhost:16827/api/cluster/status
```

---

## 9. Tham Chiếu REST API

Mọi thứ làm được trên giao diện đều có **API** tương ứng (để tự động hoá). Có **hơn 70 endpoint**.

- **Địa chỉ gốc:** `https://<máy-chủ>:16827/api/`
- **Xác thực:** thêm header `Authorization: Bearer <jwt_token>` (trừ `/api/auth/login` và `/health` là công khai).

### Một số endpoint tiêu biểu

| Phương thức | Endpoint | Mô tả |
|-------------|----------|-------|
| POST | `/api/auth/login` | Đăng nhập, lấy JWT (hiệu lực 24h) |
| POST | `/api/auth/refresh` | Làm mới JWT |
| GET/POST | `/api/hosts` | Danh sách / tạo host |
| GET/POST | `/api/allow-ips`, `/api/block-ips` | Danh sách IP trắng/đen |
| GET/POST | `/api/allow-urls`, `/api/block-urls` | Danh sách URL trắng/đen |
| GET | `/api/security-events` | Nhật ký tấn công (phân trang, lọc) |
| GET | `/api/attack-logs` | Nhật ký truy cập đầy đủ |
| GET/POST | `/api/custom-rules` | Quản lý quy tắc tuỳ chỉnh |
| GET | `/api/rules/registry` | Danh sách quy tắc dựng sẵn |
| POST | `/api/rules/reload` | Nạp nóng toàn bộ quy tắc |
| GET/POST | `/api/rule-sources` | Quản lý nguồn quy tắc |
| GET/POST | `/api/bot-patterns` | Mẫu nhận diện bot |
| GET | `/api/stats/overview`, `/api/stats/timeseries` | Số liệu thống kê |
| GET/POST | `/api/cache/*` | Thống kê & xoá cache |
| GET | `/api/cluster/status` | Trạng thái cụm |
| POST | `/api/cluster/token` | Tạo token để node mới tham gia |
| GET/PUT | `/api/crowdsec/settings` | Cấu hình CrowdSec |
| GET/PUT | `/api/ddos/config`, `/api/risk/config` | Cấu hình DDoS / điểm rủi ro |
| GET/PUT | `/api/tier-policies`, `/api/access-lists` | Chính sách tầng / danh sách truy cập |
| GET/POST | `/api/ssl`, `/api/notifications` | Chứng chỉ / cảnh báo |
| WS | `/ws/events` | Luồng sự kiện an ninh thời gian thực |
| WS | `/ws/logs` | Luồng nhật ký thời gian thực |
| GET | `/health` | Kiểm tra sức khoẻ (công khai) |

---

## 10. Tham Chiếu Dòng Lệnh (CLI)

File chạy `waf` cũng dùng được trên dòng lệnh:

```
waf [TUỲ CHỌN] <LỆNH>

Tuỳ chọn:
  -c, --config <FILE>   Đường dẫn file cấu hình [mặc định: configs/default.toml]
```

| Lệnh | Mục đích |
|------|----------|
| `run` | Khởi động proxy + API (chạy chính) |
| `migrate` | Tạo/cập nhật cấu trúc bảng trong cơ sở dữ liệu |
| `seed-admin` | Tạo tài khoản quản trị (dùng `ADMIN_PASSWORD` để đặt mật khẩu) |
| `rules` | Quản lý quy tắc: `list`, `info`, `enable`, `disable`, `reload`, `validate`, `import`, `export`, `search`, `stats` |
| `sources` | Quản lý nguồn quy tắc từ xa: `list`, `add`, `remove`, `update`, `sync` |
| `bot` | Quản lý nhận diện bot: `list`, `add`, `remove`, `test` |
| `geoip` | Quản lý cơ sở dữ liệu GeoIP: `download`, `update`, `status` |
| `community` | Tình báo cộng đồng: `status`, `enroll`, `test` |
| `crowdsec` | Tích hợp CrowdSec: `status`, `decisions`, `test`, `setup` |
| `cluster` | Phân cụm: `status`, `nodes`, `token generate`, `promote`, `demote`, `remove`, `cert-init` |

**Ví dụ thường dùng:**
```bash
waf rules list --category sqli      # liệt kê quy tắc nhóm SQLi
waf rules reload                    # nạp nóng quy tắc
waf cluster token generate --ttl 24h
waf -c /etc/waf/config.toml run
```

---

## 11. Thực Hành Bảo Mật Tốt Nhất

1. **Đổi mật khẩu quản trị ngay** — không để mật khẩu mặc định/ngẫu nhiên ban đầu.
2. **Giới hạn truy cập trang quản trị** — đặt `admin_ip_allowlist` chỉ cho dải IP của bạn.
3. **Bật xác thực 2 lớp (TOTP)** nếu hệ thống của bạn yêu cầu mức bảo mật cao.
4. **Đặt trang quản trị sau HTTPS thật** — dùng chứng chỉ hợp lệ (Caddy/nginx/Let's Encrypt) trong môi trường thật.
5. **Mật khẩu cơ sở dữ liệu mạnh** — đừng dùng mật khẩu mặc định.
6. **Bật Let's Encrypt** cho chứng chỉ HTTPS của các website được bảo vệ.
7. **Thử quy tắc mới ở chế độ bóng (Shadow Mode) hoặc `dry_run: true`** trước khi cho thực thi thật — tránh chặn nhầm khách thật.
8. **Theo dõi Dashboard thường xuyên** — chú ý đột biến tỉ lệ chặn hoặc kiểu tấn công lạ.
9. **Cấu hình cảnh báo** — nối Telegram/Webhook để được báo ngay khi có tấn công vào trang quan trọng.
10. **Tối thiểu 3 node nếu chạy cluster** — đảm bảo còn quá bán khi 1 node hỏng.
11. **Giới hạn kích thước body** (`max_request_body_bytes`) để tránh cạn bộ nhớ.
12. **Điều tra khi có honeypot hit** — đó là dấu hiệu có kẻ đang dò quét; xem xét chặn IP đó.
13. **Cập nhật quy tắc định kỳ** — đồng bộ nguồn từ xa để có bản vá CVE mới nhất.

---

## 12. Xử Lý Sự Cố Thường Gặp

| Triệu chứng | Nguyên nhân có thể | Cách xử lý |
|-------------|--------------------|------------|
| Mọi request đều bị 403 | IP nằm trong danh sách đen hoặc access-list chặn | Kiểm tra `rules/access-lists.yaml` và trang IP Rules |
| Không vào được trang quản trị | API chưa chạy hoặc cổng bị chặn | `curl -k https://localhost:16827/health` |
| Quy tắc không cập nhật | Chưa nạp nóng | Gọi `POST /api/rules/reload` hoặc `kill -HUP <pid>` hoặc `waf rules reload` |
| Chặn nhầm khách thật nhiều | Quy tắc quá nhạy | Xem Security Events, bật `dry_run`/Shadow Mode để dò |
| Node cluster mất kết nối | Chứng chỉ không khớp hoặc lỗi mạng | Kiểm tra `/api/cluster/status`, xác minh CA cert |
| Cache không chạy | Valkey không kết nối được | Kiểm tra `backend` trong `[cache]`, trạng thái circuit breaker |
| Đăng nhập thất bại | Sai thông tin hoặc lệch giờ TOTP | Chạy lại `seed-admin`; đồng bộ đồng hồ máy chủ |
| Tốn nhiều RAM | `max_size_mb` cache quá lớn | Giảm `max_size_mb` trong `[cache]` |
| Không tìm thấy mật khẩu admin | Chưa đặt `ADMIN_PASSWORD` | Xem log khởi động: `docker compose logs prx-waf \| grep -i password` |

**Lệnh kiểm tra nhanh:**
```bash
curl -k https://localhost:16827/health        # sức khoẻ
docker compose logs -f prx-waf                # log (Docker)
journalctl -u waf -f                          # log (systemd)
kill -HUP $(pgrep waf)                         # nạp nóng quy tắc
```

---

## Phụ Lục A: Bản Đồ Tính Năng (FR)

Các mã "FR-xxx" (Functional Requirement — *yêu cầu chức năng*) xuất hiện trong tài liệu tương ứng các tính năng:

| Mã FR | Tính năng | Mục liên quan |
|-------|-----------|---------------|
| FR-002 | Phân loại 4 tầng ưu tiên (Tier) | [2.3](#23-bốn-tầng-ưu-tiên-tier--fr-002) |
| FR-003 | Quy tắc tuỳ chỉnh (cây điều kiện + Rhai) | [6.8](#68-quy-tắc-tuỳ-chỉnh-trong-cơ-sở-dữ-liệu) |
| FR-004 | Giới hạn tần suất (token-bucket + cửa sổ trượt) | [5.4](#54-bảng-tóm-tắt-các-trạm-kiểm-soát) |
| FR-005 | Chống DDoS (theo IP/vân tay/tầng) | [5.1](#51-ý-tưởng-nhiều-trạm-kiểm-soát-nối-tiếp) |
| FR-006 | Challenge (câu đố/CAPTCHA, proof-of-work) | [4.20](#420-các-trang-phòng-thủ-nâng-cao) |
| FR-007 | Phân tích chuỗi proxy (X-Forwarded-For, ASN, Tor) | [5.1](#51-ý-tưởng-nhiều-trạm-kiểm-soát-nối-tiếp) |
| FR-009 | Cache thông minh theo tầng | [4.18](#418-cache-dashboard-bộ-nhớ-đệm) |
| FR-010 | Vân tay thiết bị (JA3/JA4 + HTTP/2) | [5.1](#51-ý-tưởng-nhiều-trạm-kiểm-soát-nối-tiếp) |
| FR-011 | Phát hiện bất thường hành vi | [5.3](#53-cách-chấm-điểm-rủi-ro-fr-025--giải-thích-dễ-hiểu) |
| FR-012 | Phát hiện gian lận giao dịch (TX Velocity) | [4.19](#419-tx-velocity-phát-hiện-gian-lận-giao-dịch) |
| FR-016 | Chống Traversal/SSRF | [5.4](#54-bảng-tóm-tắt-các-trạm-kiểm-soát) |
| FR-025 | Chấm điểm rủi ro tích luỹ | [5.3](#53-cách-chấm-điểm-rủi-ro-fr-025--giải-thích-dễ-hiểu) |

> ⚠️ **Lưu ý về xác thực 2 lớp (TOTP):** Cơ sở dữ liệu đã có sẵn trường lưu cấu hình TOTP, nhưng việc *bắt buộc* nhập mã TOTP khi đăng nhập tuỳ thuộc phiên bản triển khai. Nếu cần 2FA chặt chẽ, hãy kiểm tra/kích hoạt theo cấu hình hệ thống của bạn.

---

*F&G WAF (mini-waf) · Phiên bản 1.1.0 · Rust 2024 · Nền Pingora · Tài liệu giải thích dễ hiểu cho mọi đối tượng.*




// ============================================================================
// MÁY CHỦ HOST LOCAL & CLOUD (NODE.JS) - CÔNG ĐOÀN YAMAHA MOTOR PARTS VN (YPMV)
// Bảo mật Server-side:
//  - Mật khẩu băm bằng scrypt + salt ngẫu nhiên (crypto của Node.js)
//  - Phiên đăng nhập xác thực bằng HttpOnly Session Token & Authorization Header
//  - Khi chưa đăng nhập: API /api/bootstrap TUYỆT ĐỐI KHÔNG TRẢ VỀ danh sách
//    chi tiết công đoàn viên (chỉ trả về số lượng đoàn viên theo từng bộ phận)
//  - Chống Brute-Force dò mật khẩu ở tầng Server (khóa IP sau 5 lần thử sai)
// ============================================================================

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');

const PORT = Number(process.env.PORT) || 3000;
const ROOT_DIR = __dirname;
const DATA_DIR = path.join(ROOT_DIR, 'data');
const DB_FILE = path.join(DATA_DIR, 'database.json');

const MAX_ADMIN_ACCOUNTS = 30;
const SESSION_TTL_MS = 8 * 60 * 60 * 1000; // 8 giờ
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_MS = 5 * 60 * 1000; // 5 phút

// Lưu phiên đăng nhập trên RAM của Server & bộ đếm chống Brute-force theo IP
const activeSessions = new Map(); // token -> { adminId, username, expiresAt }
const loginAttemptsByIp = new Map(); // ip -> { count, lockUntil }

// Mã hóa mật khẩu chuẩn mật mã học bằng crypto.scryptSync
function hashPasswordServer(plainPassword, salt = crypto.randomBytes(16).toString('hex')) {
  const derived = crypto.scryptSync(String(plainPassword), salt, 64).toString('hex');
  return `scrypt$${salt}$${derived}`;
}

function verifyPasswordServer(plainPassword, storedHash) {
  if (!storedHash || typeof storedHash !== 'string') return false;
  if (storedHash.startsWith('scrypt$')) {
    const parts = storedHash.split('$');
    if (parts.length !== 3) return false;
    const [, salt, originalHex] = parts;
    const derivedHex = crypto.scryptSync(String(plainPassword), salt, 64).toString('hex');
    return crypto.timingSafeEqual(Buffer.from(originalHex, 'hex'), Buffer.from(derivedHex, 'hex'));
  }
  return false;
}

// Dữ liệu khởi tạo mặc định cho YPMV (6 Sheet: Prod 1, Prod 2, Prod 3, MT, Bảo an, Văn Phòng - 1.398 đoàn viên)
function loadDefault6SheetsMembers() {
  const default6File = path.join(DATA_DIR, 'default_members_6sheets.json');
  try {
    if (fs.existsSync(default6File)) {
      const parsed = JSON.parse(fs.readFileSync(default6File, 'utf8'));
      if (Array.isArray(parsed.departments) && Array.isArray(parsed.members) && parsed.members.length > 0) {
        return parsed;
      }
    }
  } catch (e) {
    console.warn('Không đọc được default_members_6sheets.json:', e.message);
  }

  // Dự phòng: Tự động trích xuất 1.398 đoàn viên từ app.js nếu người dùng chỉ tải 4 file chính lên GitHub
  try {
    const appJsPath = path.join(ROOT_DIR, 'app.js');
    if (fs.existsSync(appJsPath)) {
      const appCode = fs.readFileSync(appJsPath, 'utf8');
      const deptMatch = appCode.match(/const DEFAULT_DEPARTMENTS = (\[[\s\S]*?\]);/);
      const memMatch = appCode.match(/const DEFAULT_MEMBERS = (\[[\s\S]*?\]);\s*const DEFAULT_PLANS/);
      if (deptMatch && memMatch) {
        return {
          departments: JSON.parse(deptMatch[1]),
          members: JSON.parse(memMatch[1]),
        };
      }
    }
  } catch (e) {
    console.warn('Không trích xuất được dữ liệu mặc định từ app.js:', e.message);
  }

  return {
    departments: ['Prod 1', 'Prod 2', 'Prod 3', 'MT', 'Bảo an', 'Văn Phòng'],
    members: [],
  };
}

function getDefault22AdminsServer() {
  const defaultHash = hashPasswordServer('123456789');
  const list = [
    { id: 'adm_01', username: 'nguyenhuysang', fullName: 'Nguyễn Huy Sáng', role: 'Chủ tịch Công đoàn (Người phê duyệt)', approvalRole: 'approver' },
    { id: 'adm_root', username: 'nguyenvanhop', fullName: 'Nguyễn Văn Hợp', role: 'PCT Tài chính (Người kiểm tra 2)', approvalRole: 'checker2', isPrimary: true },
    { id: 'adm_03', username: 'phivanmanh', fullName: 'Phí Văn Mạnh', role: 'PCT Hoạt động (Người kiểm tra 1)', approvalRole: 'checker1' },
    { id: 'adm_04', username: 'nguyentrungkien', fullName: 'Nguyễn Trung Kiên', role: 'Ủy viên BCH (Người yêu cầu)', approvalRole: 'requester' },
    { id: 'adm_05', username: 'tranhuytien', fullName: 'Trần Huy Tiến', role: 'Ủy viên BCH (Người yêu cầu)', approvalRole: 'requester' },
    { id: 'adm_06', username: 'nguyenquangtrieu', fullName: 'Nguyễn Quang Triều', role: 'Ủy viên BCH (Người yêu cầu)', approvalRole: 'requester' },
    { id: 'adm_07', username: 'trankimtu', fullName: 'Trần Kim Tú', role: 'Ủy viên BCH (Người yêu cầu)', approvalRole: 'requester' },
    { id: 'adm_08', username: 'nguyenanhduc', fullName: 'Nguyễn Anh Đức', role: 'Ủy viên BCH (Người yêu cầu)', approvalRole: 'requester' },
    { id: 'adm_09', username: 'nguyenvanchien', fullName: 'Nguyễn Văn Chiến', role: 'Ủy viên BCH (Người yêu cầu)', approvalRole: 'requester' },
    { id: 'adm_10', username: 'dangmanhbinh', fullName: 'Đặng Mạnh Bính', role: 'Ủy viên BCH (Người yêu cầu)', approvalRole: 'requester' },
    { id: 'adm_11', username: 'nguyentienminh', fullName: 'Nguyễn Tiến Minh', role: 'Ủy viên BCH (Người yêu cầu)', approvalRole: 'requester' },
    { id: 'adm_12', username: 'doanhtuan', fullName: 'Đỗ Anh Tuấn', role: 'Ủy viên BCH (Người yêu cầu)', approvalRole: 'requester' },
    { id: 'adm_13', username: 'tahaiquan', fullName: 'Tạ Hải Quân', role: 'Ủy viên BCH (Người yêu cầu)', approvalRole: 'requester' },
    { id: 'adm_14', username: 'letiendung', fullName: 'Lê Tiến Dũng', role: 'Ủy viên BCH (Người yêu cầu)', approvalRole: 'requester' },
    { id: 'adm_15', username: 'nguyentienchinh', fullName: 'Nguyễn Tiến Chính', role: 'Ủy viên BCH (Người yêu cầu)', approvalRole: 'requester' },
    { id: 'adm_16', username: 'doanvantien', fullName: 'Đoàn Văn Tiến', role: 'Ủy viên BCH (Người yêu cầu)', approvalRole: 'requester' },
    { id: 'adm_17', username: 'dothihanh', fullName: 'Đỗ Thị Hạnh', role: 'Ủy viên BCH (Người yêu cầu)', approvalRole: 'requester' },
    { id: 'adm_18', username: 'duongthixuyen', fullName: 'Dương Thị Xuyến', role: 'Ủy viên BCH (Người yêu cầu)', approvalRole: 'requester' },
    { id: 'adm_19', username: 'dinhthithanhthao', fullName: 'Đinh Thị Thanh Thảo', role: 'Ủy viên BCH (Người yêu cầu)', approvalRole: 'requester' },
    { id: 'adm_20', username: 'nguyenthingoan', fullName: 'Nguyễn Thị Ngoan', role: 'Kế toán Công đoàn (Kế toán xác nhận)', approvalRole: 'accountant' },
    { id: 'adm_21', username: 'domaiphuong', fullName: 'Đỗ Mai Phương', role: 'Ủy viên BCH (Người yêu cầu)', approvalRole: 'requester' },
    { id: 'adm_22', username: 'nguyenlananh', fullName: 'Nguyễn Lan Anh', role: 'Kế toán Công đoàn (Kế toán xác nhận)', approvalRole: 'accountant' },
  ];
  return list.map((item) => ({
    ...item,
    passwordHash: defaultHash,
    createdAt: '2026-01-01',
    isPrimary: Boolean(item.isPrimary),
  }));
}

function getInitialDatabase() {
  const default6 = loadDefault6SheetsMembers();
  return {
    departments: default6.departments,
    members: default6.members,
    plans: [
      {
        id: 'p1',
        title: 'Khám sức khỏe định kỳ & Tầm soát bệnh nghề nghiệp cho Đoàn viên YPMV',
        date: '2026-11-22',
        category: 'Chăm lo phúc lợi',
        location: 'Khu vực Y tế & Nhà đa năng Công ty YPMV',
        participants: 'Toàn thể Công đoàn viên 7 bộ phận (chia theo ca)',
        status: 'Sắp diễn ra',
        desc: 'Phối hợp cùng bệnh viện tuyến trung ương tổ chức khám tổng quát, siêu âm, xét nghiệm máu và kiểm tra thính lực/hô hấp cho đoàn viên khối sản xuất Đúc, Gia công cơ khí và Lắp ráp.',
      },
      {
        id: 'p2',
        title: 'Hội nghị Đối thoại Định kỳ giữa Ban Giám đốc và Người lao động Quý IV',
        date: '2026-12-05',
        category: 'Đối thoại & Bảo vệ NLĐ',
        location: 'Phòng Họp Lớn Tầng 2 - Nhà Điều Hành YPMV',
        participants: 'BCH Công đoàn, Tổ trưởng CĐ và đại diện các bộ phận',
        status: 'Đang lấy ý kiến',
        desc: 'Tổng hợp ý kiến đóng góp từ các hòm thư Công đoàn về chế độ ca đêm, chất lượng bữa ăn ca, trang bị bảo hộ lao động mùa đông và thưởng Tết Nguyên Đán.',
      },
      {
        id: 'p3',
        title: 'Chương trình "Tết Sum Vầy - Chuyến Xe Công Đoàn YPMV Đưa Đoàn Viên Về Quê"',
        date: '2027-01-18',
        category: 'Chăm lo phúc lợi',
        location: 'Sân chính Công ty TNHH SX Phụ Tùng Yamaha Motor VN',
        participants: 'Toàn thể Công đoàn viên & Gia đình',
        status: 'Đang triển khai',
        desc: 'Trao túi quà Tết Công đoàn cho 100% đoàn viên, bốc thăm trúng thưởng xe máy Yamaha, hỗ trợ vé xe giường nằm miễn phí cho đoàn viên quê xa.',
      },
      {
        id: 'p4',
        title: 'Giải Bóng đá Nam - Nữ & Kéo co Truyền thống Yamaha Parts Cup',
        date: '2027-03-14',
        category: 'Văn hóa - Thể thao',
        location: 'Khu liên hợp thể thao KCN',
        participants: 'Đội tuyển 7 bộ phận Đúc, Gia công, Lắp ráp, QC, Bảo trì, Kho, Văn phòng',
        status: 'Đang triển khai',
        desc: 'Hoạt động thể thao thường niên chào mừng Tháng Công nhân, nâng cao sức khỏe và tinh thần đoàn kết giữa các phân xưởng sản xuất phụ tùng Yamaha.',
      },
      {
        id: 'p5',
        title: 'Lễ Tôn vinh "Bàn Tay Vàng & Sáng Kiến Kaizen Xuất Sắc YPMV"',
        date: '2027-05-08',
        category: 'Thi đua sản xuất',
        location: 'Hội trường Công ty YPMV',
        participants: 'Các cá nhân và tổ sản xuất có cải tiến kỹ thuật tiêu biểu',
        status: 'Sắp diễn ra',
        desc: 'Khen thưởng các đoàn viên có sáng kiến giảm tỷ lệ hàng lỗi (NG), tiết kiệm năng lượng tại xưởng Đúc và rút ngắn thời gian gá đặt tại xưởng Gia công CNC.',
      },
    ],
    policies: [
      { id: 'pol1', group: 'Hiếu - Hỷ - Thăm hỏi', title: 'Mừng kết hôn Đoàn viên Công đoàn', amount: '1.000.000 VNĐ / đoàn viên', desc: 'Áp dụng cho đoàn viên chính thức kết hôn (nộp bản sao Giấy đăng ký kết hôn cho Tổ trưởng Công đoàn bộ phận trong vòng 30 ngày).' },
      { id: 'pol2', group: 'Nữ công & Con đoàn viên', title: 'Chúc mừng Đoàn viên sinh con (Nam & Nữ đoàn viên)', amount: '1.000.000 VNĐ / bé', desc: 'Áp dụng cho cả đoàn viên nữ sinh con hoặc đoàn viên nam có vợ sinh con. Ngoài ra nữ đoàn viên mang thai từ tháng thứ 7 được bố trí làm ca hành chính và suất ăn bổ sung.' },
      { id: 'pol3', group: 'Hiếu - Hỷ - Thăm hỏi', title: 'Thăm hỏi ốm đau nằm viện & Phẫu thuật', amount: '500.000 - 2.000.000 VNĐ', desc: 'Đoàn viên điều trị nội trú tại bệnh viện từ 3 ngày trở lên hoặc phẫu thuật được BCH Công đoàn thăm hỏi trực tiếp và hỗ trợ kinh phí.' },
      { id: 'pol4', group: 'Hiếu - Hỷ - Thăm hỏi', title: 'Chế độ Hiếu sự (Tứ thân phụ mẫu, vợ/chồng, con)', amount: '2.000.000 VNĐ + Vòng hoa viếng', desc: 'Công đoàn cơ sở phối hợp cùng bộ phận tổ chức đoàn thăm viếng, chia buồn và hỗ trợ kịp thời cho gia đình đoàn viên.' },
      { id: 'pol5', group: 'Phúc lợi Lễ - Tết', title: 'Quà tặng Sinh nhật, Tết Nguyên Đán, Trung Thu, 8/3 & 20/10', amount: '300.000 - 1.200.000 VNĐ / dịp', desc: 'Mừng sinh nhật đoàn viên hàng tháng, tặng giỏ quà Tết Âm lịch, bánh Trung thu, quà Quốc tế Phụ nữ 8/3, Phụ nữ Việt Nam 20/10 và Quốc tế Thiếu nhi 1/6.' },
      { id: 'pol6', group: 'Nữ công & Con đoàn viên', title: 'Khuyến học "Con Công nhân viên YPMV Học giỏi - Vượt khó"', amount: '500.000 - 1.500.000 VNĐ / cháu', desc: 'Khen thưởng các cháu là con đoàn viên đạt danh hiệu Học sinh Giỏi các cấp, đạt giải thi học sinh giỏi Tỉnh/Thành phố, Quốc gia hoặc đỗ Đại học.' },
      { id: 'pol7', group: 'Bảo hộ & Điều kiện làm việc', title: 'Bữa cơm Công đoàn & Phụ cấp giải nhiệt mùa hè tại Xưởng', amount: 'Suất ăn đặc biệt + Nước điện giải/Sữa chua hàng ngày', desc: 'Tổ chức "Bữa cơm Công đoàn" định kỳ nâng cao khẩu phần dinh dưỡng và cấp phát nước chanh muối, sữa chua mát cho công nhân xưởng Đúc, Gia công trong các tháng nắng nóng.' },
      { id: 'pol8', group: 'Hiếu - Hỷ - Thăm hỏi', title: 'Quỹ Tương trợ Đoàn viên Khó khăn Đột xuất & Mái ấm Công đoàn', amount: '3.000.000 - 15.000.000 VNĐ', desc: 'Hỗ trợ đoàn viên gặp thiên tai, hỏa hoạn, bệnh hiểm nghèo hoặc hoàn cảnh gia đình đặc biệt khó khăn theo đề xuất của Tổ Công đoàn bộ phận.' },
    ],
    activities: [
      { id: 'act1', title: 'Bữa Cơm Công Đoàn YPMV - Ấm Áp Tình Đồng Nghiệp Giữa Các Ca Sản Xuất', date: '2026-10-20', tag: 'Chăm lo Đời sống', highlight: '1.450 suất ăn đặc biệt trị giá 65.000đ/suất', summary: 'Ban Chấp hành Công đoàn phối hợp cùng Ban Giám đốc tổ chức Bữa cơm Công đoàn cho toàn thể công nhân viên cả 3 ca với thực đơn bổ dưỡng, trái cây tráng miệng và trao quà mừng ngày Phụ nữ Việt Nam 20/10.', gradient: 'linear-gradient(135deg, #d90429, #9b001a)' },
      { id: 'act2', title: 'Sôi Nổi Giải Bóng Đá Nam - Nữ Công Đoàn Phụ Tùng Yamaha Motor VN', date: '2026-09-15', tag: 'Văn nghệ - Thể thao', highlight: '14 đội bóng từ 7 Bộ phận • Hơn 600 cổ động viên', summary: 'Phân xưởng Gia công cơ khí xuất sắc giành Cúp Vô địch bóng đá nam, trong khi liên quân QC - Lắp ráp đăng quang nội dung bóng đá nữ sau loạt sút luân lưu kịch tính.', gradient: 'linear-gradient(135deg, #1d4ed8, #1e3a8a)' },
      { id: 'act3', title: 'Ngày Hội Gia Đình & Vui Tết Trung Thu Cho Con Em Công Nhân Viên YPMV', date: '2026-09-25', tag: 'Chăm lo Đời sống', highlight: 'Trao 1.800 phần quà Trung thu & 240 suất học bổng', summary: 'Đêm hội trăng rằm tràn ngập tiếng cười cùng múa lân, văn nghệ thiếu nhi và lễ tuyên dương các cháu con đoàn viên đạt thành tích học tập xuất sắc.', gradient: 'linear-gradient(135deg, #d97706, #92400e)' },
      { id: 'act4', title: 'Phong Trào Thi Đua "Lao Động Giỏi - Cải Tiến Kaizen An Toàn 5S"', date: '2026-08-12', tag: 'Thi đua Kaizen', highlight: '86 đề tài Kaizen từ xưởng Đúc, Gia công, Bảo trì', summary: 'Công đoàn phát động phong trào cải tiến góc làm việc an toàn, giảm thao tác thừa và chống nóng tại khu vực lò đúc áp lực, trao thưởng nóng cho 18 tập thể và cá nhân.', gradient: 'linear-gradient(135deg, #0f766e, #115e59)' },
      { id: 'act5', title: 'Chương Trình Du Lịch Nghỉ Mát Hè Sầm Sơn - Hạ Long Cho Đoàn Viên', date: '2026-07-05', tag: 'Văn nghệ - Thể thao', highlight: '3 đợt nghỉ mát 3 ngày 2 đêm • Đêm Gala Dinner', summary: 'Hoạt động nghỉ mát thường niên giúp công nhân viên tái tạo sức lao động, gắn kết gia đình YPMV với chương trình Team Building bãi biển sôi động.', gradient: 'linear-gradient(135deg, #0284c7, #0369a1)' },
      { id: 'act6', title: 'Ngày Hội Hiến Máu Tình Nguyện "Giọt Hồng Yamaha - Sẻ Chia Sự Sống"', date: '2026-05-19', tag: 'Thiện nguyện - Xã hội', highlight: '380 đơn vị máu hiến tặng Viện Huyết học TW', summary: 'Hàng trăm đoàn viên công đoàn các bộ phận nhiệt tình đăng ký hiến máu nhân đạo, lan tỏa nét đẹp văn hóa sẻ chia vì cộng đồng của tập thể YPMV.', gradient: 'linear-gradient(135deg, #be123c, #881337)' },
    ],
    admins: getDefault22AdminsServer(),
    welfareRequests: [],
  };
}

function syncMissingDefaultAdmins(db) {
  let changed = false;
  const defaults = getDefault22AdminsServer();
  const existingMap = new Map(db.admins.map((a) => [a.username.toLowerCase(), a]));

  // Đảm bảo các tài khoản có sẵn đều có approvalRole
  db.admins.forEach((a) => {
    const def = defaults.find((d) => d.username.toLowerCase() === a.username.toLowerCase());
    if (!a.approvalRole) {
      a.approvalRole = def ? def.approvalRole : 'requester';
      changed = true;
    }
  });

  // Bổ sung các thành viên còn thiếu trong 22 đồng chí BCH (nếu chưa đủ 30)
  for (const def of defaults) {
    if (db.admins.length >= MAX_ADMIN_ACCOUNTS) break;
    if (!existingMap.has(def.username.toLowerCase())) {
      db.admins.push(def);
      existingMap.set(def.username.toLowerCase(), def);
      changed = true;
    }
  }
  return changed;
}

function loadDatabase() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
  if (!fs.existsSync(DB_FILE)) {
    const initial = getInitialDatabase();
    fs.writeFileSync(DB_FILE, JSON.stringify(initial, null, 2), 'utf8');
    return initial;
  }
  try {
    const raw = fs.readFileSync(DB_FILE, 'utf8');
    const db = JSON.parse(raw);
    let dirty = false;
    if (!Array.isArray(db.admins) || db.admins.length === 0) {
      db.admins = getDefault22AdminsServer();
      dirty = true;
    } else if (syncMissingDefaultAdmins(db)) {
      dirty = true;
    }
    if (!Array.isArray(db.welfareRequests)) {
      db.welfareRequests = [];
      dirty = true;
    }
    // Tự động nâng cấp nếu database.json trên Cloud vẫn đang chứa 13 đoàn viên mẫu cũ
    if (
      !Array.isArray(db.members) ||
      db.members.length <= 15 ||
      (Array.isArray(db.departments) && db.departments.includes('Phân xưởng Đúc (Casting)'))
    ) {
      const default6 = loadDefault6SheetsMembers();
      if (default6.members.length > 100) {
        db.departments = default6.departments;
        db.members = default6.members;
        dirty = true;
      }
    }
    if (dirty) {
      fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2), 'utf8');
    }
    return db;
  } catch (err) {
    console.error('Lỗi đọc database.json, khởi tạo lại:', err);
    const initial = getInitialDatabase();
    fs.writeFileSync(DB_FILE, JSON.stringify(initial, null, 2), 'utf8');
    return initial;
  }
}

let db = loadDatabase();

function saveDatabase() {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2), 'utf8');
}

function sanitizePublicAdmins(adminsList) {
  return (adminsList || []).map((a) => ({
    id: a.id,
    username: a.username,
    fullName: a.fullName,
    role: a.role,
    approvalRole: a.approvalRole || 'requester',
    createdAt: a.createdAt,
    isPrimary: Boolean(a.isPrimary),
  }));
}

function computeDepartmentCounts() {
  const counts = {};
  for (const dept of db.departments) {
    counts[dept] = 0;
  }
  for (const m of db.members) {
    counts[m.dept] = (counts[m.dept] || 0) + 1;
  }
  return counts;
}

function parseCookies(req) {
  const list = {};
  const cookieHeader = req.headers.cookie;
  if (!cookieHeader) return list;
  cookieHeader.split(';').forEach((cookie) => {
    const parts = cookie.split('=');
    const key = parts.shift().trim();
    const val = decodeURI(parts.join('='));
    list[key] = val;
  });
  return list;
}

function getAuthenticatedAdmin(req) {
  const cookies = parseCookies(req);
  const authHeader = req.headers['authorization'] || '';
  const bearerToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
  const token = cookies.ypmv_session || bearerToken;

  if (!token || !activeSessions.has(token)) return null;
  const session = activeSessions.get(token);
  if (Date.now() > session.expiresAt) {
    activeSessions.delete(token);
    return null;
  }
  session.expiresAt = Date.now() + SESSION_TTL_MS;
  const adminObj = db.admins.find((a) => a.id === session.adminId);
  if (!adminObj) {
    activeSessions.delete(token);
    return null;
  }
  return { admin: adminObj, token };
}

function sendJson(res, statusCode, payload, extraHeaders = {}) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'SAMEORIGIN',
    ...extraHeaders,
  });
  res.end(JSON.stringify(payload));
}

function readJsonBody(req, maxBytes = 25 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', (chunk) => {
      body += chunk;
      if (body.length > maxBytes) {
        reject(new Error('Payload quá lớn'));
        req.destroy();
      }
    });
    req.on('end', () => {
      if (!body) return resolve({});
      try {
        resolve(JSON.parse(body));
      } catch (e) {
        reject(new Error('JSON không hợp lệ'));
      }
    });
    req.on('error', reject);
  });
}

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
};

const server = http.createServer(async (req, res) => {
  const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = parsedUrl.pathname;
  const method = req.method.toUpperCase();

  // ==========================================================================
  // API ROUTES (XỬ LÝ BẢO MẬT PHÍA SERVER)
  // ==========================================================================
  if (pathname.startsWith('/api/')) {
    try {
      // 1. GET /api/bootstrap - Tải dữ liệu theo quyền (Ẩn danh sách đoàn viên nếu chưa đăng nhập)
      if (pathname === '/api/bootstrap' && method === 'GET') {
        const auth = getAuthenticatedAdmin(req);
        const deptCounts = computeDepartmentCounts();
        return sendJson(res, 200, {
          authenticated: Boolean(auth),
          currentAdmin: auth ? sanitizePublicAdmins([auth.admin])[0] : null,
          departments: db.departments,
          departmentCounts: deptCounts,
          totalMembersCount: db.members.length,
          // BẢO MẬT: Nếu chưa đăng nhập, Server trả về mảng rỗng [], hacker mở F12 cũng không thấy thông tin đoàn viên
          members: auth ? db.members : [],
          plans: db.plans,
          policies: db.policies,
          activities: db.activities,
          admins: sanitizePublicAdmins(db.admins),
          welfareRequests: auth ? (db.welfareRequests || []) : [],
        });
      }

      // 2. POST /api/login - Đăng nhập kiểm tra mật khẩu băm scrypt + Chống Brute-Force
      if (pathname === '/api/login' && method === 'POST') {
        const ip = req.socket.remoteAddress || 'unknown';
        const guard = loginAttemptsByIp.get(ip) || { count: 0, lockUntil: 0 };

        if (guard.lockUntil && Date.now() < guard.lockUntil) {
          const waitSec = Math.ceil((guard.lockUntil - Date.now()) / 1000);
          return sendJson(res, 429, {
            error: `Tài khoản tạm khóa chống dò mật khẩu! Vui lòng thử lại sau ${waitSec} giây.`,
          });
        }

        const body = await readJsonBody(req);
        const username = String(body.username || '').trim();
        const password = String(body.password || '');

        const matched = db.admins.find(
          (a) => a.username.toLowerCase() === username.toLowerCase() && verifyPasswordServer(password, a.passwordHash)
        );

        if (!matched) {
          const nextCount = guard.count + 1;
          if (nextCount >= MAX_LOGIN_ATTEMPTS) {
            loginAttemptsByIp.set(ip, { count: 0, lockUntil: Date.now() + LOCKOUT_MS });
            return sendJson(res, 429, {
              error: `Nhập sai ${MAX_LOGIN_ATTEMPTS} lần liên tiếp! Khóa đăng nhập 5 phút để bảo vệ hệ thống.`,
            });
          }
          loginAttemptsByIp.set(ip, { count: nextCount, lockUntil: 0 });
          return sendJson(res, 401, {
            error: `Sai tên đăng nhập hoặc mật khẩu! (Còn ${MAX_LOGIN_ATTEMPTS - nextCount} lần thử).`,
          });
        }

        loginAttemptsByIp.delete(ip);
        const token = crypto.randomBytes(32).toString('hex');
        activeSessions.set(token, {
          adminId: matched.id,
          username: matched.username,
          expiresAt: Date.now() + SESSION_TTL_MS,
        });

        return sendJson(
          res,
          200,
          {
            ok: true,
            token,
            currentAdmin: sanitizePublicAdmins([matched])[0],
            members: db.members,
            admins: sanitizePublicAdmins(db.admins),
            welfareRequests: db.welfareRequests || [],
          },
          {
            'Set-Cookie': `ypmv_session=${token}; HttpOnly; Path=/; SameSite=Lax; Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`,
          }
        );
      }

      // 3. POST /api/logout
      if (pathname === '/api/logout' && method === 'POST') {
        const auth = getAuthenticatedAdmin(req);
        if (auth) activeSessions.delete(auth.token);
        return sendJson(
          res,
          200,
          { ok: true },
          { 'Set-Cookie': 'ypmv_session=; HttpOnly; Path=/; Max-Age=0' }
        );
      }

      // CÁC API CẬP NHẬT DỮ LIỆU BÊN DƯỚI BẮT BUỘC PHẢI ĐĂNG NHẬP QUẢN TRỊ Ở SERVER
      const auth = getAuthenticatedAdmin(req);
      if (!auth) {
        return sendJson(res, 401, {
          error: 'Từ chối truy cập! Bạn phải đăng nhập tài khoản Quản trị mới được phép thay đổi dữ liệu trên máy chủ.',
        });
      }

      // 4. POST /api/sync - Lưu cập nhật danh sách Bộ phận, Đoàn viên, Kế hoạch, Chính sách, Hoạt động
      if (pathname === '/api/sync' && method === 'POST') {
        const body = await readJsonBody(req);
        if (Array.isArray(body.departments)) db.departments = body.departments;
        if (Array.isArray(body.members)) db.members = body.members;
        if (Array.isArray(body.plans)) db.plans = body.plans;
        if (Array.isArray(body.policies)) db.policies = body.policies;
        if (Array.isArray(body.activities)) db.activities = body.activities;
        saveDatabase();
        return sendJson(res, 200, {
          ok: true,
          departmentCounts: computeDepartmentCounts(),
          totalMembersCount: db.members.length,
        });
      }

      // 5. POST /api/admins/save - Thêm hoặc sửa tài khoản quản trị (Giới hạn tối đa 30 TK)
      if (pathname === '/api/admins/save' && method === 'POST') {
        const body = await readJsonBody(req);
        const editId = String(body.id || '').trim();
        const username = String(body.username || '').trim();
        const password = String(body.password || '');
        const fullName = String(body.fullName || '').trim();
        const role = String(body.role || 'Ủy viên BCH Công đoàn').trim();
        const validApprovalRoles = ['requester', 'checker1', 'checker2', 'approver', 'accountant'];
        const approvalRole = validApprovalRoles.includes(body.approvalRole) ? body.approvalRole : 'requester';

        if (!/^[a-zA-Z0-9_.-]+$/.test(username)) {
          return sendJson(res, 400, { error: 'Tên đăng nhập chỉ được chứa chữ cái không dấu, số và dấu gạch dưới!' });
        }

        const duplicate = db.admins.some(
          (a) => a.id !== editId && a.username.toLowerCase() === username.toLowerCase()
        );
        if (duplicate) {
          return sendJson(res, 400, { error: `Tên đăng nhập "${username}" đã tồn tại!` });
        }

        if (editId) {
          const idx = db.admins.findIndex((a) => a.id === editId);
          if (idx === -1) return sendJson(res, 404, { error: 'Không tìm thấy tài khoản cần sửa!' });
          if (password && password.length < 6) {
            return sendJson(res, 400, { error: 'Mật khẩu mới phải từ 6 ký tự trở lên!' });
          }
          db.admins[idx] = {
            ...db.admins[idx],
            username,
            passwordHash: password ? hashPasswordServer(password) : db.admins[idx].passwordHash,
            fullName,
            role,
            approvalRole: body.approvalRole ? approvalRole : (db.admins[idx].approvalRole || 'requester'),
          };
          saveDatabase();
          const currentUpdated = db.admins.find((a) => a.id === auth.admin.id);
          return sendJson(res, 200, {
            ok: true,
            admins: sanitizePublicAdmins(db.admins),
            currentAdmin: sanitizePublicAdmins([currentUpdated])[0],
          });
        }

        if (db.admins.length >= MAX_ADMIN_ACCOUNTS) {
          return sendJson(res, 400, { error: `Hệ thống chỉ cho phép tạo tối đa ${MAX_ADMIN_ACCOUNTS} tài khoản quản trị!` });
        }
        if (!password || password.length < 6) {
          return sendJson(res, 400, { error: 'Mật khẩu phải từ 6 ký tự trở lên!' });
        }

        db.admins.push({
          id: 'adm_' + Date.now(),
          username,
          passwordHash: hashPasswordServer(password),
          fullName,
          role,
          approvalRole,
          createdAt: new Date().toISOString().slice(0, 10),
          isPrimary: false,
        });
        saveDatabase();
        return sendJson(res, 200, {
          ok: true,
          admins: sanitizePublicAdmins(db.admins),
        });
      }

      // 6. POST /api/admins/delete - Xóa tài khoản quản trị phụ
      if (pathname === '/api/admins/delete' && method === 'POST') {
        const body = await readJsonBody(req);
        const targetId = String(body.id || '');
        const target = db.admins.find((a) => a.id === targetId);
        if (!target) return sendJson(res, 404, { error: 'Không tìm thấy tài khoản!' });
        if (target.id === 'adm_root' || target.isPrimary) {
          return sendJson(res, 400, { error: 'Không thể xóa tài khoản quản trị chính!' });
        }
        db.admins = db.admins.filter((a) => a.id !== targetId);
        saveDatabase();
        return sendJson(res, 200, {
          ok: true,
          admins: sanitizePublicAdmins(db.admins),
        });
      }

      // 7. POST /api/welfare/create - Tạo đơn phúc lợi mới (Bất kỳ thành viên Ban quản trị nào)
      if (pathname === '/api/welfare/create' && method === 'POST') {
        const body = await readJsonBody(req);
        const title = String(body.title || '').trim();
        const policyGroup = String(body.policyGroup || 'Hiếu - Hỷ - Thăm hỏi').trim();
        const beneficiary = String(body.beneficiary || '').trim();
        const amount = String(body.amount || '').trim();
        const reason = String(body.reason || '').trim();

        if (!title || !beneficiary) {
          return sendJson(res, 400, { error: 'Vui lòng nhập đầy đủ Nội dung đơn và Người/Bộ phận thụ hưởng!' });
        }

        if (!Array.isArray(db.welfareRequests)) db.welfareRequests = [];
        const newReq = {
          id: 'WLR-' + new Date().toISOString().slice(2, 10).replace(/-/g, '') + '-' + Math.floor(100 + Math.random() * 900),
          title,
          policyGroup,
          beneficiary,
          amount,
          reason,
          requesterId: auth.admin.id,
          requesterUsername: auth.admin.username,
          requesterName: auth.admin.fullName,
          createdAt: new Date().toISOString(),
          status: 'pending_checker1',
          rejectedStep: '',
          steps: {
            checker1: { decision: 'pending', byName: '', byUsername: '', note: '', at: '' },
            checker2: { decision: 'pending', byName: '', byUsername: '', note: '', at: '' },
            approver: { decision: 'pending', byName: '', byUsername: '', note: '', at: '' },
            accountant: { decision: 'pending', byName: '', byUsername: '', note: '', at: '' },
            requesterConfirm: { decision: 'pending', byName: '', byUsername: '', note: '', at: '' },
          },
        };
        db.welfareRequests.unshift(newReq);
        saveDatabase();
        return sendJson(res, 200, { ok: true, welfareRequests: db.welfareRequests });
      }

      // 8. POST /api/welfare/action - Duyệt / Từ chối / Xác nhận hoàn thành theo phân quyền 6 bước
      if (pathname === '/api/welfare/action' && method === 'POST') {
        const body = await readJsonBody(req);
        const id = String(body.id || '').trim();
        const decision = String(body.decision || '').trim(); // 'approve' | 'reject' | 'confirm'
        const note = String(body.note || '').trim();

        if (!Array.isArray(db.welfareRequests)) db.welfareRequests = [];
        const reqItem = db.welfareRequests.find((w) => w.id === id);
        if (!reqItem) return sendJson(res, 404, { error: 'Không tìm thấy đơn phúc lợi!' });

        const userRole = auth.admin.approvalRole || 'requester';
        const nowStr = new Date().toISOString();
        const isRequesterOwner =
          reqItem.requesterId === auth.admin.id ||
          (reqItem.requesterUsername && reqItem.requesterUsername.toLowerCase() === auth.admin.username.toLowerCase());

        if (decision === 'cancel') {
          if (!isRequesterOwner) {
            return sendJson(res, 403, { error: `Chỉ người tạo đơn (${reqItem.requesterName}) mới có quyền hủy đơn này!` });
          }
          if (!reqItem.status || !reqItem.status.startsWith('pending_')) {
            return sendJson(res, 400, { error: 'Chỉ có thể hủy đơn khi đơn chưa hoàn thành!' });
          }
          if (!note) {
            return sendJson(res, 400, { error: 'Vui lòng nhập chú thích / lý do hủy đơn!' });
          }
          reqItem.steps.requesterConfirm = {
            decision: 'cancelled',
            byName: auth.admin.fullName,
            byUsername: auth.admin.username,
            note,
            at: nowStr,
          };
          reqItem.status = 'cancelled';
          saveDatabase();
          return sendJson(res, 200, { ok: true, welfareRequests: db.welfareRequests });
        }

        const stepOrder = {
          pending_checker1: { key: 'checker1', role: 'checker1', label: 'Người kiểm tra 1 (PCT Hoạt động)', next: 'pending_checker2' },
          pending_checker2: { key: 'checker2', role: 'checker2', label: 'Người kiểm tra 2 (PCT Tài chính)', next: 'pending_approver' },
          pending_approver: { key: 'approver', role: 'approver', label: 'Người phê duyệt (Chủ tịch)', next: 'pending_accountant' },
          pending_accountant: { key: 'accountant', role: 'accountant', label: 'Kế toán xác nhận', next: 'pending_confirm' },
        };

        if (reqItem.status === 'pending_confirm') {
          if (!isRequesterOwner) {
            return sendJson(res, 403, { error: `Chỉ người yêu cầu tạo đơn (${reqItem.requesterName}) mới được quyền xác nhận hoàn thành!` });
          }
          if (decision !== 'confirm' && decision !== 'approve') {
            return sendJson(res, 400, { error: 'Hành động không hợp lệ ở bước xác nhận hoàn thành!' });
          }
          reqItem.steps.requesterConfirm = {
            decision: 'confirmed',
            byName: auth.admin.fullName,
            byUsername: auth.admin.username,
            note: note || 'Đã xác nhận hoàn thành',
            at: nowStr,
          };
          reqItem.status = 'completed';
          saveDatabase();
          return sendJson(res, 200, { ok: true, welfareRequests: db.welfareRequests });
        }

        const currentRule = stepOrder[reqItem.status];
        if (!currentRule) {
          return sendJson(res, 400, { error: 'Đơn này đã kết thúc (Hoàn thành hoặc Đã từ chối), không thể thao tác tiếp!' });
        }
        if (userRole !== currentRule.role) {
          return sendJson(res, 403, { error: `Bạn không có quyền thao tác bước "${currentRule.label}"!` });
        }
        if (decision !== 'approve' && decision !== 'reject') {
          return sendJson(res, 400, { error: 'Lựa chọn duyệt phải là Đồng ý hoặc Không đồng ý!' });
        }

        reqItem.steps[currentRule.key] = {
          decision: decision === 'approve' ? 'approved' : 'rejected',
          byName: auth.admin.fullName,
          byUsername: auth.admin.username,
          note,
          at: nowStr,
        };
        if (decision === 'approve') {
          reqItem.status = currentRule.next;
        } else {
          reqItem.status = 'rejected';
          reqItem.rejectedStep = currentRule.label;
        }
        saveDatabase();
        return sendJson(res, 200, { ok: true, welfareRequests: db.welfareRequests });
      }

      // 9. POST /api/welfare/delete - Xóa đơn phúc lợi (Người tạo đơn khi chưa hoàn thành hoặc Quản trị chính)
      if (pathname === '/api/welfare/delete' && method === 'POST') {
        const body = await readJsonBody(req);
        const id = String(body.id || '').trim();
        if (!Array.isArray(db.welfareRequests)) db.welfareRequests = [];
        const reqItem = db.welfareRequests.find((w) => w.id === id);
        if (!reqItem) return sendJson(res, 404, { error: 'Không tìm thấy đơn phúc lợi!' });

        const isOwner =
          reqItem.requesterId === auth.admin.id ||
          (reqItem.requesterUsername && reqItem.requesterUsername.toLowerCase() === auth.admin.username.toLowerCase());
        if (!isOwner && !auth.admin.isPrimary) {
          return sendJson(res, 403, { error: 'Chỉ người tạo đơn hoặc Quản trị chính mới có quyền xóa đơn này!' });
        }
        db.welfareRequests = db.welfareRequests.filter((w) => w.id !== id);
        saveDatabase();
        return sendJson(res, 200, { ok: true, welfareRequests: db.welfareRequests });
      }

      return sendJson(res, 404, { error: 'API không tồn tại' });
    } catch (err) {
      console.error('API Error:', err);
      return sendJson(res, 500, { error: err.message || 'Lỗi máy chủ nội bộ' });
    }
  }

  // ==========================================================================
  // PHỤC VỤ FILE TĨNH GIAO DIỆN WEB (CHẶN TRUY CẬP THƯ MỤC DATA & SERVER.JS)
  // ==========================================================================
  let safePath = pathname === '/' ? '/index.html' : pathname;
  safePath = path.normalize(safePath).replace(/^(\.\.[/\\])+/, '');

  if (
    safePath.includes('database.json') ||
    safePath.startsWith('\\data') ||
    safePath.startsWith('/data') ||
    safePath.includes('server.js')
  ) {
    res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' });
    return res.end('403 Forbidden - Khu vực dữ liệu bảo mật của máy chủ.');
  }

  const filePath = path.join(ROOT_DIR, safePath);
  if (!filePath.startsWith(ROOT_DIR)) {
    res.writeHead(403);
    return res.end('Forbidden');
  }

  fs.readFile(filePath, (err, content) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end('404 Không tìm thấy tệp');
    }
    const ext = path.extname(filePath).toLowerCase();
    res.writeHead(200, {
      'Content-Type': MIME_TYPES[ext] || 'application/octet-stream',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'SAMEORIGIN',
    });
    res.end(content);
  });
});

function getLocalLanIp() {
  const nets = os.networkInterfaces();
  for (const name of Object.keys(nets)) {
    for (const net of nets[name]) {
      if (net.family === 'IPv4' && !net.internal) {
        return net.address;
      }
    }
  }
  return 'localhost';
}

server.listen(PORT, '0.0.0.0', () => {
  const lanIp = getLocalLanIp();
  console.log('====================================================================');
  console.log('  HOST CONG DOAN YAMAHA MOTOR PARTS VIET NAM (YPMV) DA KHOI DONG!');
  console.log(`  - Truy cap tren may nay:   http://localhost:${PORT}`);
  console.log(`  - Truy cap mang LAN YPMV:  http://${lanIp}:${PORT}`);
  console.log('  - CSDL Bao mat luu tai:    ./data/database.json');
  console.log('====================================================================');
});

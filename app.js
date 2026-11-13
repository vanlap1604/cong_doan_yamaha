// ============================================================================
// CỔNG THÔNG TIN CÔNG ĐOÀN CÔNG TY TNHH SẢN XUẤT PHỤ TÙNG YAMAHA MOTOR VIỆT NAM
// HỖ TRỢ ĐỒNG THỜI:
//   1. CHẾ ĐỘ MÁY CHỦ HOST LOCAL / CLOUD (http://localhost:3000) -> Bảo mật 100% Server-side
//   2. CHẾ ĐỘ MỞ FILE TRỰC TIẾP (file://) -> Dự phòng localStorage có băm SHA-256
// ============================================================================
(() => {
'use strict';

const STORAGE_KEYS = {
  DEPARTMENTS: 'ypmv_union_departments_v2_6sheets',
  MEMBERS: 'ypmv_union_members_v2_6sheets',
  PLANS: 'ypmv_union_plans_v1',
  POLICIES: 'ypmv_union_policies_v1',
  ACTIVITIES: 'ypmv_union_activities_v1',
  ADMINS: 'ypmv_union_admins_v1',
  WELFARE_REQUESTS: 'ypmv_union_welfare_requests_v1',
  SESSION: 'ypmv_union_active_session_v1',
  LOGIN_GUARD: 'ypmv_union_login_guard_v1',
  SERVER_TOKEN: 'ypmv_union_server_token_v1',
};

const MAX_ADMIN_ACCOUNTS = 30;
const SESSION_TIMEOUT_MS = 30 * 60 * 1000;
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_DURATION_MS = 5 * 60 * 1000;
const PASSWORD_SALT = 'YPMV_UNION_SALT_2026_#';

function hashPasswordSync(plainPassword) {
  const str = PASSWORD_SALT + String(plainPassword || '');
  const K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ];
  const rightRotate = (value, amount) => (value >>> amount) | (value << (32 - amount));
  const utf8 = unescape(encodeURIComponent(str));
  const words = [];
  for (let i = 0; i < utf8.length; i++) {
    words[i >> 2] |= (utf8.charCodeAt(i) & 0xff) << (24 - (i % 4) * 8);
  }
  const bitLength = utf8.length * 8;
  words[bitLength >> 5] |= 0x80 << (24 - (bitLength % 32));
  words[(((bitLength + 64) >> 9) << 4) + 15] = bitLength;

  let H = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ];
  const W = new Array(64);
  for (let j = 0; j < words.length; j += 16) {
    let [a, b, c, d, e, f, g, h] = H;
    for (let i = 0; i < 64; i++) {
      if (i < 16) {
        W[i] = words[j + i] | 0;
      } else {
        const gamma0x = W[i - 15];
        const gamma0 = rightRotate(gamma0x, 7) ^ rightRotate(gamma0x, 18) ^ (gamma0x >>> 3);
        const gamma1x = W[i - 2];
        const gamma1 = rightRotate(gamma1x, 17) ^ rightRotate(gamma1x, 19) ^ (gamma1x >>> 10);
        W[i] = (W[i - 16] + gamma0 + W[i - 7] + gamma1) | 0;
      }
      const ch = (e & f) ^ (~e & g);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const sigma0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
      const sigma1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
      const t1 = (h + sigma1 + ch + K[i] + W[i]) | 0;
      const t2 = (sigma0 + maj) | 0;
      h = g;
      g = f;
      f = e;
      e = (d + t1) | 0;
      d = c;
      c = b;
      b = a;
      a = (t1 + t2) | 0;
    }
    H = H.map((v, idx) => (v + [a, b, c, d, e, f, g, h][idx]) | 0);
  }
  return 'sha256$' + H.map((v) => (v >>> 0).toString(16).padStart(8, '0')).join('');
}

function verifyPassword(inputPlain, storedValue) {
  if (!storedValue) return false;
  if (storedValue.startsWith('sha256$')) {
    return hashPasswordSync(inputPlain) === storedValue;
  }
  return inputPlain === storedValue;
}

function sanitizeRichHtml(dirtyHtml) {
  const parser = new DOMParser();
  const doc = parser.parseFromString(String(dirtyHtml || ''), 'text/html');

  const allowedTags = new Set([
    'P', 'BR', 'B', 'STRONG', 'I', 'EM', 'U', 'H3', 'H4', 'UL', 'OL', 'LI',
    'FIGURE', 'FIGCAPTION', 'IMG', 'VIDEO', 'IFRAME', 'SPAN', 'DIV', 'BLOCKQUOTE',
  ]);
  const allowedAttrs = {
    IMG: new Set(['src', 'alt', 'class']),
    VIDEO: new Set(['src', 'controls', 'preload', 'class']),
    IFRAME: new Set(['src', 'allowfullscreen', 'class']),
    FIGURE: new Set(['class']),
    FIGCAPTION: new Set(['class']),
    SPAN: new Set(['class']),
    DIV: new Set(['class']),
    P: new Set(['class']),
  };

  function cleanNode(node) {
    const children = Array.from(node.childNodes);
    for (const child of children) {
      if (child.nodeType === Node.ELEMENT_NODE) {
        const tag = child.tagName.toUpperCase();
        if (!allowedTags.has(tag)) {
          child.remove();
          continue;
        }
        const attrs = Array.from(child.attributes);
        const tagAllowed = allowedAttrs[tag] || new Set();
        for (const attr of attrs) {
          const name = attr.name.toLowerCase();
          const val = (attr.value || '').trim();
          if (!tagAllowed.has(name)) {
            child.removeAttribute(attr.name);
            continue;
          }
          if (name === 'src') {
            const isSafeSrc =
              /^https:\/\//i.test(val) ||
              /^http:\/\//i.test(val) ||
              /^data:image\/(png|jpeg|jpg|webp|gif);base64,/i.test(val) ||
              /^data:video\/(mp4|webm|ogg|quicktime);base64,/i.test(val);
            if (!isSafeSrc) {
              child.remove();
              break;
            }
            if (tag === 'IFRAME' && !/^https:\/\/(www\.)?youtube(-nocookie)?\.com\/embed\//i.test(val)) {
              child.remove();
              break;
            }
          }
        }
        cleanNode(child);
      } else if (child.nodeType === Node.COMMENT_NODE) {
        child.remove();
      }
    }
  }

  cleanNode(doc.body);
  return doc.body.innerHTML;
}

function sanitizeExcelCellText(val) {
  const s = String(val || '').trim();
  if (/^[=+\-@]/.test(s)) {
    return "'" + s;
  }
  return s;
}

const DEFAULT_ADMINS = [
  { id: 'adm_01', username: 'nguyenhuysang', passwordHash: hashPasswordSync('123456789'), fullName: 'Đ/c Nguyễn Huy Sáng', role: 'Chủ tịch Công đoàn (Người phê duyệt)', approvalRole: 'approver', createdAt: '2026-01-01', isPrimary: false },
  { id: 'adm_root', username: 'nguyenvanhop', passwordHash: hashPasswordSync('123456789'), fullName: 'Đ/c Nguyễn Văn Hợp', role: 'PCT Tài chính (Người kiểm tra 2)', approvalRole: 'checker2', createdAt: '2026-01-01', isPrimary: true },
  { id: 'adm_03', username: 'phivanmanh', passwordHash: hashPasswordSync('123456789'), fullName: 'Đ/c Phí Văn Mạnh', role: 'PCT Hoạt động (Người kiểm tra 1)', approvalRole: 'checker1', createdAt: '2026-01-01', isPrimary: false },
  { id: 'adm_04', username: 'nguyentrungkien', passwordHash: hashPasswordSync('123456789'), fullName: 'Đ/c Nguyễn Trung Kiên', role: 'Ủy viên BCH Công đoàn', approvalRole: 'requester', createdAt: '2026-01-01', isPrimary: false },
  { id: 'adm_05', username: 'tranhuytien', passwordHash: hashPasswordSync('123456789'), fullName: 'Đ/c Trần Huy Tiến', role: 'Ủy viên BCH Công đoàn', approvalRole: 'requester', createdAt: '2026-01-01', isPrimary: false },
  { id: 'adm_06', username: 'nguyenquangtrieu', passwordHash: hashPasswordSync('123456789'), fullName: 'Đ/c Nguyễn Quang Triều', role: 'Ủy viên BCH Công đoàn', approvalRole: 'requester', createdAt: '2026-01-01', isPrimary: false },
  { id: 'adm_07', username: 'trankimtu', passwordHash: hashPasswordSync('123456789'), fullName: 'Đ/c Trần Kim Tú', role: 'Ủy viên BCH Công đoàn', approvalRole: 'requester', createdAt: '2026-01-01', isPrimary: false },
  { id: 'adm_08', username: 'nguyenanhduc', passwordHash: hashPasswordSync('123456789'), fullName: 'Đ/c Nguyễn Anh Đức', role: 'Ủy viên BCH Công đoàn', approvalRole: 'requester', createdAt: '2026-01-01', isPrimary: false },
  { id: 'adm_09', username: 'nguyenvanchien', passwordHash: hashPasswordSync('123456789'), fullName: 'Đ/c Nguyễn Văn Chiến', role: 'Ủy viên BCH Công đoàn', approvalRole: 'requester', createdAt: '2026-01-01', isPrimary: false },
  { id: 'adm_10', username: 'dangmanhbinh', passwordHash: hashPasswordSync('123456789'), fullName: 'Đ/c Đặng Mạnh Bính', role: 'Ủy viên BCH Công đoàn', approvalRole: 'requester', createdAt: '2026-01-01', isPrimary: false },
  { id: 'adm_11', username: 'nguyentienminh', passwordHash: hashPasswordSync('123456789'), fullName: 'Đ/c Nguyễn Tiến Minh', role: 'Ủy viên BCH Công đoàn', approvalRole: 'requester', createdAt: '2026-01-01', isPrimary: false },
  { id: 'adm_12', username: 'doanhtuan', passwordHash: hashPasswordSync('123456789'), fullName: 'Đ/c Đỗ Anh Tuấn', role: 'Ủy viên BCH Công đoàn', approvalRole: 'requester', createdAt: '2026-01-01', isPrimary: false },
  { id: 'adm_13', username: 'tahaiquan', passwordHash: hashPasswordSync('123456789'), fullName: 'Đ/c Tạ Hải Quân', role: 'Ủy viên BCH Công đoàn', approvalRole: 'requester', createdAt: '2026-01-01', isPrimary: false },
  { id: 'adm_14', username: 'letiendung', passwordHash: hashPasswordSync('123456789'), fullName: 'Đ/c Lê Tiến Dũng', role: 'Ủy viên BCH Công đoàn', approvalRole: 'requester', createdAt: '2026-01-01', isPrimary: false },
  { id: 'adm_15', username: 'nguyentienchinh', passwordHash: hashPasswordSync('123456789'), fullName: 'Đ/c Nguyễn Tiến Chính', role: 'Ủy viên BCH Công đoàn', approvalRole: 'requester', createdAt: '2026-01-01', isPrimary: false },
  { id: 'adm_16', username: 'doanvantien', passwordHash: hashPasswordSync('123456789'), fullName: 'Đ/c Đoàn Văn Tiến', role: 'Ủy viên BCH Công đoàn', approvalRole: 'requester', createdAt: '2026-01-01', isPrimary: false },
  { id: 'adm_17', username: 'dothihanh', passwordHash: hashPasswordSync('123456789'), fullName: 'Đ/c Đỗ Thị Hạnh', role: 'Ủy viên BCH Công đoàn', approvalRole: 'requester', createdAt: '2026-01-01', isPrimary: false },
  { id: 'adm_18', username: 'duongthixuyen', passwordHash: hashPasswordSync('123456789'), fullName: 'Đ/c Dương Thị Xuyến', role: 'Ủy viên BCH Công đoàn', approvalRole: 'requester', createdAt: '2026-01-01', isPrimary: false },
  { id: 'adm_19', username: 'dinhthithanhthao', passwordHash: hashPasswordSync('123456789'), fullName: 'Đ/c Đinh Thị Thanh Thảo', role: 'Ủy viên BCH Công đoàn', approvalRole: 'requester', createdAt: '2026-01-01', isPrimary: false },
  { id: 'adm_20', username: 'nguyenthingoan', passwordHash: hashPasswordSync('123456789'), fullName: 'Đ/c Nguyễn Thị Ngoan', role: 'Kế toán Công đoàn', approvalRole: 'accountant', createdAt: '2026-01-01', isPrimary: false },
  { id: 'adm_21', username: 'domaiphuong', passwordHash: hashPasswordSync('123456789'), fullName: 'Đ/c Đỗ Mai Phương', role: 'Ủy viên BCH Công đoàn', approvalRole: 'requester', createdAt: '2026-01-01', isPrimary: false },
  { id: 'adm_22', username: 'nguyenlananh', passwordHash: hashPasswordSync('123456789'), fullName: 'Đ/c Nguyễn Lan Anh', role: 'Kế toán Công đoàn', approvalRole: 'accountant', createdAt: '2026-01-01', isPrimary: false },
];

const DEFAULT_DEPARTMENTS = ["Prod 1", "Prod 2", "Prod 3", "MT", "Bảo an", "Văn Phòng"];

const DEFAULT_MEMBERS = [{"id": "Prod 1_1_S00028", "stt": 1, "code": "S00028", "name": "Thân Anh Quỳnh", "dept": "Prod 1", "department": "Production 1", "shop": "", "group": "", "note": ""}, {"id": "Prod 1_2_W00140", "stt": 2, "code": "W00140", "name": "Lê Thị Thủy", "dept": "Prod 1", "department": "Production 1", "shop": "K0-Finishing", "group": "", "note": ""}, {"id": "Prod 1_3_W00154", "stt": 3, "code": "W00154", "name": "Nguyễn Thị Phương Dung", "dept": "Prod 1", "department": "Production 1", "shop": "K0-Finishing", "group": "", "note": ""}, {"id": "Prod 1_4_W00191", "stt": 4, "code": "W00191", "name": "Lê Văn Tính", "dept": "Prod 1", "department": "Production 1", "shop": "K0-Finishing", "group": "", "note": ""}, {"id": "Prod 1_5_W00192", "stt": 5, "code": "W00192", "name": "Lê Văn Toàn", "dept": "Prod 1", "department": "Production 1", "shop": "K0-Finishing", "group": "", "note": ""}, {"id": "Prod 1_6_W00211", "stt": 6, "code": "W00211", "name": "Nguyễn Văn Cường", "dept": "Prod 1", "department": "Production 1", "shop": "K0-Finishing", "group": "", "note": ""}, {"id": "Prod 1_7_W00264", "stt": 7, "code": "W00264", "name": "Nguyễn Văn Phong", "dept": "Prod 1", "department": "Production 1", "shop": "K0-Finishing", "group": "", "note": ""}, {"id": "Prod 1_8_W00272", "stt": 8, "code": "W00272", "name": "Nguyễn Thị Lương", "dept": "Prod 1", "department": "Production 1", "shop": "K0-Finishing", "group": "", "note": ""}, {"id": "Prod 1_9_W00274", "stt": 9, "code": "W00274", "name": "Nguyễn Thị Mai Hạnh", "dept": "Prod 1", "department": "Production 1", "shop": "K0-Finishing", "group": "", "note": ""}, {"id": "Prod 1_10_W00276", "stt": 10, "code": "W00276", "name": "Nguyễn Thị Oanh", "dept": "Prod 1", "department": "Production 1", "shop": "K0-Finishing", "group": "", "note": ""}, {"id": "Prod 1_11_W00282", "stt": 11, "code": "W00282", "name": "Nguyễn Thị Thoả", "dept": "Prod 1", "department": "Production 1", "shop": "K0-Finishing", "group": "", "note": ""}, {"id": "Prod 1_12_W00533", "stt": 12, "code": "W00533", "name": "Phạm Văn Khải", "dept": "Prod 1", "department": "Production 1", "shop": "K0-Finishing", "group": "", "note": ""}, {"id": "Prod 1_13_W00654", "stt": 13, "code": "W00654", "name": "Đồng Văn Tân", "dept": "Prod 1", "department": "Production 1", "shop": "K0-Finishing", "group": "", "note": ""}, {"id": "Prod 1_14_W00658", "stt": 14, "code": "W00658", "name": "Bùi Tử Phòng", "dept": "Prod 1", "department": "Production 1", "shop": "K0-Finishing", "group": "", "note": ""}, {"id": "Prod 1_15_W00691", "stt": 15, "code": "W00691", "name": "Phan Văn Trường", "dept": "Prod 1", "department": "Production 1", "shop": "K0-Finishing", "group": "", "note": ""}, {"id": "Prod 1_16_W01470", "stt": 16, "code": "W01470", "name": "Đỗ Thị Đam", "dept": "Prod 1", "department": "Production 1", "shop": "K0-Finishing", "group": "", "note": ""}, {"id": "Prod 1_17_W02106", "stt": 17, "code": "W02106", "name": "Dương Thị Nhung", "dept": "Prod 1", "department": "Production 1", "shop": "K0-Finishing", "group": "", "note": ""}, {"id": "Prod 1_18_W02442", "stt": 18, "code": "W02442", "name": "Đỗ Anh Hùng", "dept": "Prod 1", "department": "Production 1", "shop": "K0-Finishing", "group": "", "note": ""}, {"id": "Prod 1_19_W03001", "stt": 19, "code": "W03001", "name": "Hoàng Văn Ánh", "dept": "Prod 1", "department": "Production 1", "shop": "K0-Finishing", "group": "", "note": ""}, {"id": "Prod 1_20_W04232", "stt": 20, "code": "W04232", "name": "Phan Ngọc An", "dept": "Prod 1", "department": "Production 1", "shop": "K0-Finishing", "group": "", "note": ""}, {"id": "Prod 1_21_W04768", "stt": 21, "code": "W04768", "name": "Lê Việt Tân", "dept": "Prod 1", "department": "Production 1", "shop": "K0-Finishing", "group": "", "note": ""}, {"id": "Prod 1_22_W04919", "stt": 22, "code": "W04919", "name": "Nguyễn Thị Thu Hiền", "dept": "Prod 1", "department": "Production 1", "shop": "K0-Finishing", "group": "", "note": ""}, {"id": "Prod 1_23_W04942", "stt": 23, "code": "W04942", "name": "Nguyễn Thị Thùy", "dept": "Prod 1", "department": "Production 1", "shop": "K0-Finishing", "group": "", "note": ""}, {"id": "Prod 1_24_W04995", "stt": 24, "code": "W04995", "name": "Lỗ Thị Mai", "dept": "Prod 1", "department": "Production 1", "shop": "K0-Finishing", "group": "", "note": ""}, {"id": "Prod 1_25_W05569", "stt": 25, "code": "W05569", "name": "Dương Thị Thúy Quỳnh", "dept": "Prod 1", "department": "Production 1", "shop": "K0-Finishing", "group": "", "note": ""}, {"id": "Prod 1_26_W05573", "stt": 26, "code": "W05573", "name": "Phạm Thị Phương Thảo", "dept": "Prod 1", "department": "Production 1", "shop": "K0-Finishing", "group": "", "note": ""}, {"id": "Prod 1_27_W05576", "stt": 27, "code": "W05576", "name": "Quang Văn Xơ", "dept": "Prod 1", "department": "Production 1", "shop": "K0-Finishing", "group": "", "note": ""}, {"id": "Prod 1_28_W05579", "stt": 28, "code": "W05579", "name": "Vương Xuân Chiến", "dept": "Prod 1", "department": "Production 1", "shop": "K0-Finishing", "group": "", "note": ""}, {"id": "Prod 1_29_W05580", "stt": 29, "code": "W05580", "name": "La Văn Dương", "dept": "Prod 1", "department": "Production 1", "shop": "K0-Finishing", "group": "", "note": ""}, {"id": "Prod 1_30_W05770", "stt": 30, "code": "W05770", "name": "Nguyễn Thanh Tú", "dept": "Prod 1", "department": "Production 1", "shop": "K0-Finishing", "group": "", "note": ""}, {"id": "Prod 1_31_W00062", "stt": 31, "code": "W00062", "name": "Đinh Anh Tuấn", "dept": "Prod 1", "department": "Production 1", "shop": "LP-Head Cylinder", "group": "", "note": ""}, {"id": "Prod 1_32_W00074", "stt": 32, "code": "W00074", "name": "Nguyễn Quang Tuấn", "dept": "Prod 1", "department": "Production 1", "shop": "LP-Head Cylinder", "group": "", "note": ""}, {"id": "Prod 1_33_W00084", "stt": 33, "code": "W00084", "name": "Phạm Quang Minh", "dept": "Prod 1", "department": "Production 1", "shop": "LP-Head Cylinder", "group": "", "note": ""}, {"id": "Prod 1_34_W00550", "stt": 34, "code": "W00550", "name": "Thái Việt Hùng", "dept": "Prod 1", "department": "Production 1", "shop": "LP-Head Cylinder", "group": "", "note": ""}, {"id": "Prod 1_35_W00556", "stt": 35, "code": "W00556", "name": "Nguyễn Tiến Vượng", "dept": "Prod 1", "department": "Production 1", "shop": "LP-Head Cylinder", "group": "", "note": ""}, {"id": "Prod 1_36_W01616", "stt": 36, "code": "W01616", "name": "Nguyễn Hữu Sinh", "dept": "Prod 1", "department": "Production 1", "shop": "LP-Head Cylinder", "group": "", "note": ""}, {"id": "Prod 1_37_W01746", "stt": 37, "code": "W01746", "name": "Nguyễn Văn Khà", "dept": "Prod 1", "department": "Production 1", "shop": "LP-Head Cylinder", "group": "", "note": ""}, {"id": "Prod 1_38_W02924", "stt": 38, "code": "W02924", "name": "Trần Văn Khánh", "dept": "Prod 1", "department": "Production 1", "shop": "LP-Head Cylinder", "group": "", "note": ""}, {"id": "Prod 1_39_W02930", "stt": 39, "code": "W02930", "name": "Hoàng Xuân Tiến", "dept": "Prod 1", "department": "Production 1", "shop": "LP-Head Cylinder", "group": "", "note": ""}, {"id": "Prod 1_40_W02932", "stt": 40, "code": "W02932", "name": "Hán Xuân Lợi", "dept": "Prod 1", "department": "Production 1", "shop": "LP-Head Cylinder", "group": "", "note": ""}, {"id": "Prod 1_41_W03435", "stt": 41, "code": "W03435", "name": "Lê Trọng Nam", "dept": "Prod 1", "department": "Production 1", "shop": "LP-Head Cylinder", "group": "", "note": ""}, {"id": "Prod 1_42_W03635", "stt": 42, "code": "W03635", "name": "Bùi Văn Linh", "dept": "Prod 1", "department": "Production 1", "shop": "LP-Head Cylinder", "group": "", "note": ""}, {"id": "Prod 1_43_W03933", "stt": 43, "code": "W03933", "name": "Phùng Văn Hưng", "dept": "Prod 1", "department": "Production 1", "shop": "LP-Head Cylinder", "group": "", "note": ""}, {"id": "Prod 1_44_W04271", "stt": 44, "code": "W04271", "name": "Nguyễn Quang Điệp", "dept": "Prod 1", "department": "Production 1", "shop": "LP-Head Cylinder", "group": "", "note": ""}, {"id": "Prod 1_45_W04284", "stt": 45, "code": "W04284", "name": "Văn Thế Hùng", "dept": "Prod 1", "department": "Production 1", "shop": "LP-Head Cylinder", "group": "", "note": ""}, {"id": "Prod 1_46_W04530", "stt": 46, "code": "W04530", "name": "Nguyễn Sơn Tùng", "dept": "Prod 1", "department": "Production 1", "shop": "LP-Head Cylinder", "group": "", "note": ""}, {"id": "Prod 1_47_W04865", "stt": 47, "code": "W04865", "name": "Nguyễn Hoàng Thạch", "dept": "Prod 1", "department": "Production 1", "shop": "LP-Head Cylinder", "group": "", "note": ""}, {"id": "Prod 1_48_W04904", "stt": 48, "code": "W04904", "name": "Phạm Văn Bách", "dept": "Prod 1", "department": "Production 1", "shop": "LP-Head Cylinder", "group": "", "note": ""}, {"id": "Prod 1_49_W04937", "stt": 49, "code": "W04937", "name": "Bùi Văn Sáu", "dept": "Prod 1", "department": "Production 1", "shop": "LP-Head Cylinder", "group": "", "note": ""}, {"id": "Prod 1_50_W05306", "stt": 50, "code": "W05306", "name": "Nguyễn Văn Nam", "dept": "Prod 1", "department": "Production 1", "shop": "LP-Head Cylinder", "group": "", "note": ""}, {"id": "Prod 1_51_W05314", "stt": 51, "code": "W05314", "name": "Nguyễn Văn Thạc", "dept": "Prod 1", "department": "Production 1", "shop": "LP-Head Cylinder", "group": "", "note": ""}, {"id": "Prod 1_52_W05384", "stt": 52, "code": "W05384", "name": "Nguyễn Đức Lương", "dept": "Prod 1", "department": "Production 1", "shop": "LP-Head Cylinder", "group": "", "note": ""}, {"id": "Prod 1_53_W05521", "stt": 53, "code": "W05521", "name": "Trần Văn Thỏa", "dept": "Prod 1", "department": "Production 1", "shop": "LP-Head Cylinder", "group": "", "note": ""}, {"id": "Prod 1_54_W05891", "stt": 54, "code": "W05891", "name": "Nguyễn Việt Hoàng", "dept": "Prod 1", "department": "Production 1", "shop": "LP-Head Cylinder", "group": "", "note": ""}, {"id": "Prod 1_55_W00085", "stt": 55, "code": "W00085", "name": "Phạm Văn Thắng", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_56_W00166", "stt": 56, "code": "W00166", "name": "Trần Thị Dung", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_57_W00261", "stt": 57, "code": "W00261", "name": "Nguyễn Bá Quyên", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_58_W00287", "stt": 58, "code": "W00287", "name": "Nguyễn Thị Vân An", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_59_W00369", "stt": 59, "code": "W00369", "name": "Đặng Văn Chỉnh", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_60_W00527", "stt": 60, "code": "W00527", "name": "Nguyễn Văn Nghĩa", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_61_W01055", "stt": 61, "code": "W01055", "name": "Đỗ Thị Tình", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_62_W01157", "stt": 62, "code": "W01157", "name": "Ngô Thị Sự", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_63_W01188", "stt": 63, "code": "W01188", "name": "Nguyễn Thị Hường", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_64_W01284", "stt": 64, "code": "W01284", "name": "Trần Văn Kiên", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_65_W02044", "stt": 65, "code": "W02044", "name": "Trần Thị Hương", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_66_W02057", "stt": 66, "code": "W02057", "name": "Nguyễn Thành Ngân", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_67_W02141", "stt": 67, "code": "W02141", "name": "Hoàng Thị Ngọc Ánh", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_68_W02886", "stt": 68, "code": "W02886", "name": "Nguyễn Thu Hoài", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_69_W02958", "stt": 69, "code": "W02958", "name": "Phan Thanh Thủy", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_70_W02960", "stt": 70, "code": "W02960", "name": "Trần Thị Nhung", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_71_W03171", "stt": 71, "code": "W03171", "name": "Nguyễn Văn Thu", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_72_W03380", "stt": 72, "code": "W03380", "name": "Lê Tuấn Nam", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_73_W03583", "stt": 73, "code": "W03583", "name": "Nguyễn Thị Hương", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_74_W03985", "stt": 74, "code": "W03985", "name": "Phan Thị Phương Lan", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_75_W04293", "stt": 75, "code": "W04293", "name": "Mai Văn Lượng", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_76_W04327", "stt": 76, "code": "W04327", "name": "Nguyễn Xuân Trường", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_77_W04376", "stt": 77, "code": "W04376", "name": "Nguyễn Hữu Việt", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_78_W04411", "stt": 78, "code": "W04411", "name": "Nguyễn Thị Minh Phương", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_79_W04453", "stt": 79, "code": "W04453", "name": "Lương Đắc Giới", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_80_W04457", "stt": 80, "code": "W04457", "name": "Lê Văn Thành", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_81_W04610", "stt": 81, "code": "W04610", "name": "Ngô Văn Hạnh", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_82_W04646", "stt": 82, "code": "W04646", "name": "Đỗ Đăng Phương", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_83_W04709", "stt": 83, "code": "W04709", "name": "Đỗ Thị Ánh", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_84_W04810", "stt": 84, "code": "W04810", "name": "Nguyễn Văn Chánh", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_85_W04821", "stt": 85, "code": "W04821", "name": "Lưu Văn Diện", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_86_W04906", "stt": 86, "code": "W04906", "name": "Đào Duy Cường", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_87_W04911", "stt": 87, "code": "W04911", "name": "Nguyễn Thế Dũng", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_88_W04930", "stt": 88, "code": "W04930", "name": "Phan Văn Nhì", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_89_W04965", "stt": 89, "code": "W04965", "name": "Đào Xuân Cường", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_90_W05045", "stt": 90, "code": "W05045", "name": "Nguyễn Văn Hiện", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_91_W05099", "stt": 91, "code": "W05099", "name": "Nguyễn Thanh Bình", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_92_W05100", "stt": 92, "code": "W05100", "name": "Đỗ Văn Bộ", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_93_W05103", "stt": 93, "code": "W05103", "name": "Hoàng Văn Cường", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_94_W05118", "stt": 94, "code": "W05118", "name": "Vương Văn Hùng", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_95_W05127", "stt": 95, "code": "W05127", "name": "Phạm Thị Lý", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_96_W05134", "stt": 96, "code": "W05134", "name": "Nguyễn Văn Nam", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_97_W05138", "stt": 97, "code": "W05138", "name": "Nguyễn Thị Kim Oanh", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_98_W05346", "stt": 98, "code": "W05346", "name": "Nguyễn Bá Đăng", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_99_W05375", "stt": 99, "code": "W05375", "name": "Nguyễn Quang Vũ", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_100_W05383", "stt": 100, "code": "W05383", "name": "Đỗ Văn Linh", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_101_W05403", "stt": 101, "code": "W05403", "name": "Đồng Văn Quyền", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_102_W05520", "stt": 102, "code": "W05520", "name": "Nguyễn Quang Tiến", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_103_W05552", "stt": 103, "code": "W05552", "name": "Nguyễn Thị Nhài", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_104_W05565", "stt": 104, "code": "W05565", "name": "Chu Văn Hòa", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_105_W05568", "stt": 105, "code": "W05568", "name": "Đỗ Văn Mơ", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_106_W05570", "stt": 106, "code": "W05570", "name": "Hoàng Thị Oanh", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_107_W05572", "stt": 107, "code": "W05572", "name": "Nguyễn Thị Hường", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_108_W05575", "stt": 108, "code": "W05575", "name": "Hoàng Quốc Đạt", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_109_W05582", "stt": 109, "code": "W05582", "name": "Phan Thanh Vinh", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_110_W05726", "stt": 110, "code": "W05726", "name": "Hoàng Văn Chưởng", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_111_W05727", "stt": 111, "code": "W05727", "name": "Khổng Minh Trường", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_112_W05737", "stt": 112, "code": "W05737", "name": "Nguyễn Văn Cường", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_113_W05739", "stt": 113, "code": "W05739", "name": "Nguyễn Văn Hoàng", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_114_W05754", "stt": 114, "code": "W05754", "name": "Trịnh Hồng Hải", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_115_W05781", "stt": 115, "code": "W05781", "name": "Nguyễn Thị Yến", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_116_W05830", "stt": 116, "code": "W05830", "name": "Đỗ Thị Hương", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_117_W05847", "stt": 117, "code": "W05847", "name": "Nguyễn Thị Gia Liên", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_118_W05866", "stt": 118, "code": "W05866", "name": "Nguyễn Thị Yên", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_119_W05867", "stt": 119, "code": "W05867", "name": "Trần Thị Ngà", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_120_W05868", "stt": 120, "code": "W05868", "name": "Nguyễn Thị Tâm", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_121_W05869", "stt": 121, "code": "W05869", "name": "Ngô Thị Hà", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_122_W05870", "stt": 122, "code": "W05870", "name": "Nguyễn Thị Nga", "dept": "Prod 1", "department": "Production 1", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 1_123_W00081", "stt": 123, "code": "W00081", "name": "Vũ Tuấn Tú", "dept": "Prod 1", "department": "Production 1", "shop": "Melting", "group": "", "note": ""}, {"id": "Prod 1_124_W00255", "stt": 124, "code": "W00255", "name": "Trần Công Tráng", "dept": "Prod 1", "department": "Production 1", "shop": "Melting", "group": "", "note": ""}, {"id": "Prod 1_125_W00542", "stt": 125, "code": "W00542", "name": "Trịnh Ngọc Châu", "dept": "Prod 1", "department": "Production 1", "shop": "Melting", "group": "", "note": ""}, {"id": "Prod 1_126_W01040", "stt": 126, "code": "W01040", "name": "Đinh Văn Minh", "dept": "Prod 1", "department": "Production 1", "shop": "Melting", "group": "", "note": ""}, {"id": "Prod 1_127_W02794", "stt": 127, "code": "W02794", "name": "Lê Quang Vũ", "dept": "Prod 1", "department": "Production 1", "shop": "Melting", "group": "", "note": ""}, {"id": "Prod 1_128_W03406", "stt": 128, "code": "W03406", "name": "Nguyễn Mạnh Linh", "dept": "Prod 1", "department": "Production 1", "shop": "Melting", "group": "", "note": ""}, {"id": "Prod 1_129_W03447", "stt": 129, "code": "W03447", "name": "Hoàng Văn Cương", "dept": "Prod 1", "department": "Production 1", "shop": "Melting", "group": "", "note": ""}, {"id": "Prod 1_130_W04424", "stt": 130, "code": "W04424", "name": "Phan Thanh Nam", "dept": "Prod 1", "department": "Production 1", "shop": "Melting", "group": "", "note": ""}, {"id": "Prod 1_131_W00023", "stt": 131, "code": "W00023", "name": "Nguyễn Phạm Tuân", "dept": "Prod 1", "department": "Production 1", "shop": "Mold Coating", "group": "", "note": ""}, {"id": "Prod 1_132_W00300", "stt": 132, "code": "W00300", "name": "Hà Minh Đức", "dept": "Prod 1", "department": "Production 1", "shop": "Mold Coating", "group": "", "note": ""}, {"id": "Prod 1_133_W00671", "stt": 133, "code": "W00671", "name": "Nguyễn Ngọc Linh", "dept": "Prod 1", "department": "Production 1", "shop": "Mold Coating", "group": "", "note": ""}, {"id": "Prod 1_134_W03385", "stt": 134, "code": "W03385", "name": "Nguyễn Văn Tân", "dept": "Prod 1", "department": "Production 1", "shop": "Mold Coating", "group": "", "note": ""}, {"id": "Prod 1_135_W03774", "stt": 135, "code": "W03774", "name": "Trần Mạnh Hùng", "dept": "Prod 1", "department": "Production 1", "shop": "Mold Coating", "group": "", "note": ""}, {"id": "Prod 1_136_W04482", "stt": 136, "code": "W04482", "name": "Nguyễn Văn Trung", "dept": "Prod 1", "department": "Production 1", "shop": "Mold Coating", "group": "", "note": ""}, {"id": "Prod 1_137_W04912", "stt": 137, "code": "W04912", "name": "Nguyễn Trung Dũng", "dept": "Prod 1", "department": "Production 1", "shop": "Mold Coating", "group": "", "note": ""}, {"id": "Prod 1_138_S00039", "stt": 138, "code": "S00039", "name": "Nguyễn Huy Sáng", "dept": "Prod 1", "department": "Production 1", "shop": "Officer", "group": "", "note": ""}, {"id": "Prod 1_139_S00151", "stt": 139, "code": "S00151", "name": "Nguyễn Quyết", "dept": "Prod 1", "department": "Production 1", "shop": "Officer", "group": "", "note": ""}, {"id": "Prod 1_140_S00154", "stt": 140, "code": "S00154", "name": "Đoàn Thị Thu Hà", "dept": "Prod 1", "department": "Production 1", "shop": "Officer", "group": "", "note": ""}, {"id": "Prod 1_141_S00186", "stt": 141, "code": "S00186", "name": "Lê Tiến Hùng", "dept": "Prod 1", "department": "Production 1", "shop": "Officer", "group": "", "note": ""}, {"id": "Prod 1_142_S00280", "stt": 142, "code": "S00280", "name": "Nguyễn Thị Thanh Bình", "dept": "Prod 1", "department": "Production 1", "shop": "Officer", "group": "", "note": ""}, {"id": "Prod 1_143_S00281", "stt": 143, "code": "S00281", "name": "Lư Thanh Phương", "dept": "Prod 1", "department": "Production 1", "shop": "Officer", "group": "", "note": ""}, {"id": "Prod 1_144_W00055", "stt": 144, "code": "W00055", "name": "Đinh Thị Thanh Thảo", "dept": "Prod 1", "department": "Production 1", "shop": "Officer", "group": "", "note": ""}, {"id": "Prod 1_145_W00475", "stt": 145, "code": "W00475", "name": "Nguyễn Thị Hiền", "dept": "Prod 1", "department": "Production 1", "shop": "Officer", "group": "", "note": ""}, {"id": "Prod 1_146_W00535", "stt": 146, "code": "W00535", "name": "Tạ Hải Quân", "dept": "Prod 1", "department": "Production 1", "shop": "Officer", "group": "", "note": ""}, {"id": "Prod 1_147_W00670", "stt": 147, "code": "W00670", "name": "Cao Văn Lịch", "dept": "Prod 1", "department": "Production 1", "shop": "Officer", "group": "", "note": ""}, {"id": "Prod 1_148_W02952", "stt": 148, "code": "W02952", "name": "Nguyễn Thị Hoa", "dept": "Prod 1", "department": "Production 1", "shop": "Officer", "group": "", "note": ""}, {"id": "Prod 1_149_W03022", "stt": 149, "code": "W03022", "name": "Nguyễn Thị Hiền", "dept": "Prod 1", "department": "Production 1", "shop": "Officer", "group": "", "note": ""}, {"id": "Prod 1_150_W04113", "stt": 150, "code": "W04113", "name": "Đinh Thị Nga", "dept": "Prod 1", "department": "Production 1", "shop": "Officer", "group": "", "note": ""}, {"id": "Prod 1_151_W04734", "stt": 151, "code": "W04734", "name": "Đàm Thị Xoa", "dept": "Prod 1", "department": "Production 1", "shop": "Officer", "group": "", "note": ""}, {"id": "Prod 1_152_W05382", "stt": 152, "code": "W05382", "name": "Hoàng Thị Huyền", "dept": "Prod 1", "department": "Production 1", "shop": "Officer", "group": "", "note": ""}, {"id": "Prod 1_153_W05567", "stt": 153, "code": "W05567", "name": "Đỗ Thị Quỳnh", "dept": "Prod 1", "department": "Production 1", "shop": "Officer", "group": "", "note": ""}, {"id": "Prod 1_154_W00049", "stt": 154, "code": "W00049", "name": "Nguyễn Thị Toàn", "dept": "Prod 1", "department": "Production 1", "shop": "Packing", "group": "", "note": ""}, {"id": "Prod 1_155_W00163", "stt": 155, "code": "W00163", "name": "Phạm Kim Cúc", "dept": "Prod 1", "department": "Production 1", "shop": "Packing", "group": "", "note": ""}, {"id": "Prod 1_156_W00172", "stt": 156, "code": "W00172", "name": "Bùi Văn Hà", "dept": "Prod 1", "department": "Production 1", "shop": "Packing", "group": "", "note": ""}, {"id": "Prod 1_157_W00220", "stt": 157, "code": "W00220", "name": "Phạm Ngọc Yến", "dept": "Prod 1", "department": "Production 1", "shop": "Packing", "group": "", "note": ""}, {"id": "Prod 1_158_W00284", "stt": 158, "code": "W00284", "name": "Nguyễn Thị Thu Huyền", "dept": "Prod 1", "department": "Production 1", "shop": "Packing", "group": "", "note": ""}, {"id": "Prod 1_159_W02103", "stt": 159, "code": "W02103", "name": "Trần Văn Công", "dept": "Prod 1", "department": "Production 1", "shop": "Packing", "group": "", "note": ""}, {"id": "Prod 1_160_W03455", "stt": 160, "code": "W03455", "name": "Vương Đình Huy", "dept": "Prod 1", "department": "Production 1", "shop": "Packing", "group": "", "note": ""}, {"id": "Prod 1_161_W05136", "stt": 161, "code": "W05136", "name": "Hoàng Thị Ngọc", "dept": "Prod 1", "department": "Production 1", "shop": "Packing", "group": "", "note": ""}, {"id": "Prod 1_162_W05872", "stt": 162, "code": "W05872", "name": "Đỗ Thị Mận", "dept": "Prod 1", "department": "Production 1", "shop": "Packing", "group": "", "note": ""}, {"id": "Prod 1_163_W00041", "stt": 163, "code": "W00041", "name": "Nguyễn Thị Thảo", "dept": "Prod 1", "department": "Production 1", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 1_164_W00043", "stt": 164, "code": "W00043", "name": "Nguyễn Thị Hạnh", "dept": "Prod 1", "department": "Production 1", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 1_165_W00141", "stt": 165, "code": "W00141", "name": "Lữ Thị Minh", "dept": "Prod 1", "department": "Production 1", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 1_166_W00178", "stt": 166, "code": "W00178", "name": "Đỗ Xuân Dũng", "dept": "Prod 1", "department": "Production 1", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 1_167_W00269", "stt": 167, "code": "W00269", "name": "Nguyễn Thị Lan", "dept": "Prod 1", "department": "Production 1", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 1_168_W00466", "stt": 168, "code": "W00466", "name": "La Thị Lý", "dept": "Prod 1", "department": "Production 1", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 1_169_W00474", "stt": 169, "code": "W00474", "name": "Nguyễn Thị Chung", "dept": "Prod 1", "department": "Production 1", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 1_170_W00491", "stt": 170, "code": "W00491", "name": "Đỗ Việt Hùng", "dept": "Prod 1", "department": "Production 1", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 1_171_W00668", "stt": 171, "code": "W00668", "name": "Nguyễn Mạnh Dũng", "dept": "Prod 1", "department": "Production 1", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 1_172_W01023", "stt": 172, "code": "W01023", "name": "Nguyễn Thị Hiên", "dept": "Prod 1", "department": "Production 1", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 1_173_W01265", "stt": 173, "code": "W01265", "name": "Dương Quốc Tuấn", "dept": "Prod 1", "department": "Production 1", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 1_174_W02949", "stt": 174, "code": "W02949", "name": "Tạ Văn Nghiệp", "dept": "Prod 1", "department": "Production 1", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 1_175_W03999", "stt": 175, "code": "W03999", "name": "Nguyễn Thị Hải", "dept": "Prod 1", "department": "Production 1", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 1_176_W04008", "stt": 176, "code": "W04008", "name": "Trần Thị Hường", "dept": "Prod 1", "department": "Production 1", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 1_177_W04654", "stt": 177, "code": "W04654", "name": "Phan Thị Hương", "dept": "Prod 1", "department": "Production 1", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 1_178_W04795", "stt": 178, "code": "W04795", "name": "Dương Thị Na", "dept": "Prod 1", "department": "Production 1", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 1_179_W04855", "stt": 179, "code": "W04855", "name": "Vũ Văn Ngọ", "dept": "Prod 1", "department": "Production 1", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 1_180_W04944", "stt": 180, "code": "W04944", "name": "Đỗ Văn Tứ", "dept": "Prod 1", "department": "Production 1", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 1_181_W04948", "stt": 181, "code": "W04948", "name": "Lê Văn Việt", "dept": "Prod 1", "department": "Production 1", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 1_182_W05111", "stt": 182, "code": "W05111", "name": "Nguyễn Khánh Giang", "dept": "Prod 1", "department": "Production 1", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 1_183_W05137", "stt": 183, "code": "W05137", "name": "Nguyễn Thị Nhung", "dept": "Prod 1", "department": "Production 1", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 1_184_W05318", "stt": 184, "code": "W05318", "name": "Bùi Cao Tiệp", "dept": "Prod 1", "department": "Production 1", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 1_185_W05629", "stt": 185, "code": "W05629", "name": "Nguyễn Văn Mốt", "dept": "Prod 1", "department": "Production 1", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 1_186_W05721", "stt": 186, "code": "W05721", "name": "Đồng Văn Giang", "dept": "Prod 1", "department": "Production 1", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 1_187_W05871", "stt": 187, "code": "W05871", "name": "Phạm Thị Thủy", "dept": "Prod 1", "department": "Production 1", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 2_1_W00096", "stt": 1, "code": "W00096", "name": "Đinh Thị Như Hoa", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Assy", "note": ""}, {"id": "Prod 2_2_W00097", "stt": 2, "code": "W00097", "name": "Nguyễn Tiến Minh", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Grinding", "note": ""}, {"id": "Prod 2_3_W00099", "stt": 3, "code": "W00099", "name": "Nguyễn Thị Sợi", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Assy", "note": ""}, {"id": "Prod 2_4_W00102", "stt": 4, "code": "W00102", "name": "Nguyễn Thị Chung", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Honing", "note": ""}, {"id": "Prod 2_5_W00113", "stt": 5, "code": "W00113", "name": "Lê Văn Sơn", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Grinding", "note": ""}, {"id": "Prod 2_6_W00135", "stt": 6, "code": "W00135", "name": "Đỗ Thị Hương Giang", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Hardturning", "note": ""}, {"id": "Prod 2_7_W00328", "stt": 7, "code": "W00328", "name": "Nguyễn Văn Chinh", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Grinding", "note": ""}, {"id": "Prod 2_8_W00343", "stt": 8, "code": "W00343", "name": "Hoàng Thị Oanh", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Honing", "note": ""}, {"id": "Prod 2_9_W00351", "stt": 9, "code": "W00351", "name": "Nguyễn Thị Hà", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Assy", "note": ""}, {"id": "Prod 2_10_W00401", "stt": 10, "code": "W00401", "name": "Nguyễn Văn Tuấn", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Hardturning", "note": ""}, {"id": "Prod 2_11_W00428", "stt": 11, "code": "W00428", "name": "Hoàng Ngọc Anh", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Grinding", "note": ""}, {"id": "Prod 2_12_W00497", "stt": 12, "code": "W00497", "name": "Hoàng Văn Hiền", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Assy", "note": ""}, {"id": "Prod 2_13_W00806", "stt": 13, "code": "W00806", "name": "Nguyễn Văn Quỳnh", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Assy", "note": ""}, {"id": "Prod 2_14_W00820", "stt": 14, "code": "W00820", "name": "Nguyễn Như Toàn", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Grinding", "note": ""}, {"id": "Prod 2_15_W00821", "stt": 15, "code": "W00821", "name": "Dương Tuấn Anh", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Grinding", "note": ""}, {"id": "Prod 2_16_W00883", "stt": 16, "code": "W00883", "name": "Ngô Đức Lợi", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Assy", "note": ""}, {"id": "Prod 2_17_W00891", "stt": 17, "code": "W00891", "name": "Trương Minh Quang", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Hardturning", "note": ""}, {"id": "Prod 2_18_W00903", "stt": 18, "code": "W00903", "name": "Nguyễn Văn Toàn", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Assy", "note": ""}, {"id": "Prod 2_19_W00918", "stt": 19, "code": "W00918", "name": "Cù Thị Cúc", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Assy", "note": ""}, {"id": "Prod 2_20_W01121", "stt": 20, "code": "W01121", "name": "Đỗ Thị Tuyết Mai", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Assy", "note": ""}, {"id": "Prod 2_21_W01123", "stt": 21, "code": "W01123", "name": "Phùng Thị Kim Liên", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Hardturning", "note": ""}, {"id": "Prod 2_22_W01200", "stt": 22, "code": "W01200", "name": "Đào Xuân Quảng", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Assy", "note": ""}, {"id": "Prod 2_23_W01225", "stt": 23, "code": "W01225", "name": "Hà Văn Tuân", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Grinding", "note": ""}, {"id": "Prod 2_24_W01269", "stt": 24, "code": "W01269", "name": "Nguyễn Thị Quý", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Assy", "note": ""}, {"id": "Prod 2_25_W01277", "stt": 25, "code": "W01277", "name": "Nguyễn Thị Nguyệt", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Hardturning", "note": ""}, {"id": "Prod 2_26_W01280", "stt": 26, "code": "W01280", "name": "Lê Thị Hường", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Hardturning", "note": ""}, {"id": "Prod 2_27_W01282", "stt": 27, "code": "W01282", "name": "Đào Thị Ninh", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Assy", "note": ""}, {"id": "Prod 2_28_W01283", "stt": 28, "code": "W01283", "name": "Lê Thị Mơ", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Assy", "note": ""}, {"id": "Prod 2_29_W01297", "stt": 29, "code": "W01297", "name": "Đào Nam Hải", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Assy", "note": ""}, {"id": "Prod 2_30_W01360", "stt": 30, "code": "W01360", "name": "Nguyễn Thị Nhung", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Assy", "note": ""}, {"id": "Prod 2_31_W01707", "stt": 31, "code": "W01707", "name": "Nguyễn Văn Toản", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Grinding", "note": ""}, {"id": "Prod 2_32_W01749", "stt": 32, "code": "W01749", "name": "Nguyễn Tiến Lộc", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Grinding", "note": ""}, {"id": "Prod 2_33_W01807", "stt": 33, "code": "W01807", "name": "Hoàng Thị Quang", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Assy", "note": ""}, {"id": "Prod 2_34_W01845", "stt": 34, "code": "W01845", "name": "Phan Thị Nhung", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Hardturning", "note": ""}, {"id": "Prod 2_35_W01970", "stt": 35, "code": "W01970", "name": "Nguyễn Văn Sơn", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Grinding", "note": ""}, {"id": "Prod 2_36_W02014", "stt": 36, "code": "W02014", "name": "Đỗ Thị Ngân", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Hardturning", "note": ""}, {"id": "Prod 2_37_W02021", "stt": 37, "code": "W02021", "name": "Nguyễn Thị Canh", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Assy", "note": ""}, {"id": "Prod 2_38_W02025", "stt": 38, "code": "W02025", "name": "Lê Thị Hoa", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Assy", "note": ""}, {"id": "Prod 2_39_W02026", "stt": 39, "code": "W02026", "name": "Nguyễn Thị Phượng", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Hardturning", "note": ""}, {"id": "Prod 2_40_W02035", "stt": 40, "code": "W02035", "name": "Đào Thị Dung", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Hardturning", "note": ""}, {"id": "Prod 2_41_W02037", "stt": 41, "code": "W02037", "name": "Trịnh Thị Dung", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Assy", "note": ""}, {"id": "Prod 2_42_W02191", "stt": 42, "code": "W02191", "name": "Nguyễn Thị Hường", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Hardturning", "note": ""}, {"id": "Prod 2_43_W02195", "stt": 43, "code": "W02195", "name": "Trần Thị Thu Thủy", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Hardturning", "note": ""}, {"id": "Prod 2_44_W02200", "stt": 44, "code": "W02200", "name": "Nguyễn Thị Dung", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Hardturning", "note": ""}, {"id": "Prod 2_45_W02234", "stt": 45, "code": "W02234", "name": "Vũ Văn Tuyên", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Grinding", "note": ""}, {"id": "Prod 2_46_W02294", "stt": 46, "code": "W02294", "name": "Phan Thị Bảo", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Assy", "note": ""}, {"id": "Prod 2_47_W02351", "stt": 47, "code": "W02351", "name": "Phùng Thị Liên", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Assy", "note": ""}, {"id": "Prod 2_48_W02417", "stt": 48, "code": "W02417", "name": "Vũ Thị Hằng", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Hardturning", "note": ""}, {"id": "Prod 2_49_W02734", "stt": 49, "code": "W02734", "name": "Nguyễn Thị Nhâm", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Hardturning", "note": ""}, {"id": "Prod 2_50_W02749", "stt": 50, "code": "W02749", "name": "Nguyễn Thị Hạnh", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Hardturning", "note": ""}, {"id": "Prod 2_51_W02813", "stt": 51, "code": "W02813", "name": "Đồng Thị Hồng", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Hardturning", "note": ""}, {"id": "Prod 2_52_W02895", "stt": 52, "code": "W02895", "name": "Mai Thị Thủy", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Assy", "note": ""}, {"id": "Prod 2_53_W03027", "stt": 53, "code": "W03027", "name": "Nguyễn Thị Lâm", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Assy", "note": ""}, {"id": "Prod 2_54_W03249", "stt": 54, "code": "W03249", "name": "Ngô Văn Sơn", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Grinding", "note": ""}, {"id": "Prod 2_55_W03321", "stt": 55, "code": "W03321", "name": "Nguyễn Văn Hoàng", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Grinding", "note": ""}, {"id": "Prod 2_56_W03721", "stt": 56, "code": "W03721", "name": "Hoàng Bích Ngọc", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Hardturning", "note": ""}, {"id": "Prod 2_57_W04121", "stt": 57, "code": "W04121", "name": "Trương Thị Dinh", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Assy", "note": ""}, {"id": "Prod 2_58_W04419", "stt": 58, "code": "W04419", "name": "Vũ Thu Hằng", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Assy", "note": ""}, {"id": "Prod 2_59_W04852", "stt": 59, "code": "W04852", "name": "Lưu Quang Minh", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Assy", "note": ""}, {"id": "Prod 2_60_W05013", "stt": 60, "code": "W05013", "name": "Nguyễn Thị Thêu", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Hardturning", "note": ""}, {"id": "Prod 2_61_W05143", "stt": 61, "code": "W05143", "name": "Trần Văn Quý", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Hardturning", "note": ""}, {"id": "Prod 2_62_W05172", "stt": 62, "code": "W05172", "name": "Ngô Thị Xuân", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Assy", "note": ""}, {"id": "Prod 2_63_W05251", "stt": 63, "code": "W05251", "name": "Nguyễn Thế Giáp", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Grinding", "note": ""}, {"id": "Prod 2_64_W05367", "stt": 64, "code": "W05367", "name": "Đào Văn Khánh", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Assy", "note": ""}, {"id": "Prod 2_65_W05389", "stt": 65, "code": "W05389", "name": "Trần Thị Như Quỳnh", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Hardturning", "note": ""}, {"id": "Prod 2_66_W05451", "stt": 66, "code": "W05451", "name": "Trần Văn Mạnh", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Assy", "note": ""}, {"id": "Prod 2_67_W05499", "stt": 67, "code": "W05499", "name": "Nguyễn Thị Hồng Châm", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Assy", "note": ""}, {"id": "Prod 2_68_W05510", "stt": 68, "code": "W05510", "name": "Nguyễn Văn Thanh", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Grinding", "note": ""}, {"id": "Prod 2_69_W05526", "stt": 69, "code": "W05526", "name": "Hoàng Ngọc Hưng", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Hardturning", "note": ""}, {"id": "Prod 2_70_W05540", "stt": 70, "code": "W05540", "name": "Nguyễn Thị Thương", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Assy", "note": ""}, {"id": "Prod 2_71_W05541", "stt": 71, "code": "W05541", "name": "Dương Thị Ngần", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Honing", "note": ""}, {"id": "Prod 2_72_W05594", "stt": 72, "code": "W05594", "name": "La Thị Trang", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Assy", "note": ""}, {"id": "Prod 2_73_W05600", "stt": 73, "code": "W05600", "name": "Lê Thị Lý", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Honing", "note": ""}, {"id": "Prod 2_74_W05602", "stt": 74, "code": "W05602", "name": "Lưu Thị Nhâm", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Hardturning", "note": ""}, {"id": "Prod 2_75_W05604", "stt": 75, "code": "W05604", "name": "Ngô Thị Hương", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Assy", "note": ""}, {"id": "Prod 2_76_W05615", "stt": 76, "code": "W05615", "name": "Nguyễn Thị Ngà", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Hardturning", "note": ""}, {"id": "Prod 2_77_W05625", "stt": 77, "code": "W05625", "name": "Nguyễn Văn Dương", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Grinding", "note": ""}, {"id": "Prod 2_78_W05626", "stt": 78, "code": "W05626", "name": "Nguyễn Văn Hải", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Hardturning", "note": ""}, {"id": "Prod 2_79_W05627", "stt": 79, "code": "W05627", "name": "Nguyễn Văn Hưng", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Assy", "note": ""}, {"id": "Prod 2_80_W05628", "stt": 80, "code": "W05628", "name": "Nguyễn Văn Lâm", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Honing", "note": ""}, {"id": "Prod 2_81_W05635", "stt": 81, "code": "W05635", "name": "Lê Thị Ngọc Lương", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Assy", "note": ""}, {"id": "Prod 2_82_W05641", "stt": 82, "code": "W05641", "name": "Lê Văn Khanh", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Hardturning", "note": ""}, {"id": "Prod 2_83_W05649", "stt": 83, "code": "W05649", "name": "Cao Thị Phương Thảo", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Assy", "note": ""}, {"id": "Prod 2_84_W05651", "stt": 84, "code": "W05651", "name": "Đào Thị Hoàn", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Hardturning", "note": ""}, {"id": "Prod 2_85_W05652", "stt": 85, "code": "W05652", "name": "Nguyễn Thị Hồng Tình", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Assy", "note": ""}, {"id": "Prod 2_86_W05653", "stt": 86, "code": "W05653", "name": "Nguyễn Thúy Nga", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Assy", "note": ""}, {"id": "Prod 2_87_W05667", "stt": 87, "code": "W05667", "name": "Phạm Văn Hảo", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Honing", "note": ""}, {"id": "Prod 2_88_W05705", "stt": 88, "code": "W05705", "name": "Vương Xuân Tuyến", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Hardturning", "note": ""}, {"id": "Prod 2_89_W05759", "stt": 89, "code": "W05759", "name": "Trần Thị Thu Hương", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Assy", "note": ""}, {"id": "Prod 2_90_W05766", "stt": 90, "code": "W05766", "name": "Nguyễn Văn Sơn", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Assy", "note": ""}, {"id": "Prod 2_91_W05775", "stt": 91, "code": "W05775", "name": "Đỗ Thị Nhung", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Hardturning", "note": ""}, {"id": "Prod 2_92_W05804", "stt": 92, "code": "W05804", "name": "Nguyễn Hải Đăng", "dept": "Prod 2", "department": "Production 2", "shop": "After Heat treatment", "group": "Grinding", "note": ""}, {"id": "Prod 2_93_W00030", "stt": 93, "code": "W00030", "name": "Phạm Tràng Hải", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Axle", "note": ""}, {"id": "Prod 2_94_W00091", "stt": 94, "code": "W00091", "name": "Hoàng Minh Khương", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Broach, Hob", "note": ""}, {"id": "Prod 2_95_W00092", "stt": 95, "code": "W00092", "name": "Hoàng Ngọc Huy", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Gear Senban", "note": ""}, {"id": "Prod 2_96_W00103", "stt": 96, "code": "W00103", "name": "Nguyễn Tuấn Sang", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "GPDN, Boss", "note": ""}, {"id": "Prod 2_97_W00115", "stt": 97, "code": "W00115", "name": "Ngô Văn Đức", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "GPDN, Boss", "note": ""}, {"id": "Prod 2_98_W00134", "stt": 98, "code": "W00134", "name": "Đào Thị Loan", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Gear Senban", "note": ""}, {"id": "Prod 2_99_W00145", "stt": 99, "code": "W00145", "name": "Nguyễn Thị Thúy Mây", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "GPDN, Boss", "note": ""}, {"id": "Prod 2_100_W00168", "stt": 100, "code": "W00168", "name": "Trần Thị Hoa", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Axle", "note": ""}, {"id": "Prod 2_101_W00171", "stt": 101, "code": "W00171", "name": "Vương Thị Hồng", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Gear Senban", "note": ""}, {"id": "Prod 2_102_W00241", "stt": 102, "code": "W00241", "name": "Vũ Thị Thuỷ", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Axle", "note": ""}, {"id": "Prod 2_103_W00285", "stt": 103, "code": "W00285", "name": "Nguyễn Thị Thuý Hằng", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Axle", "note": ""}, {"id": "Prod 2_104_W00319", "stt": 104, "code": "W00319", "name": "Nguyễn Hữu Tiến", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "GPDN, Boss", "note": ""}, {"id": "Prod 2_105_W00337", "stt": 105, "code": "W00337", "name": "Đàm Thị Hoa", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Axle", "note": ""}, {"id": "Prod 2_106_W00339", "stt": 106, "code": "W00339", "name": "Đào Thị Liên", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Axle", "note": ""}, {"id": "Prod 2_107_W00346", "stt": 107, "code": "W00346", "name": "Ngô Thị Hồng Ni", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Shaving, Shaper", "note": ""}, {"id": "Prod 2_108_W00356", "stt": 108, "code": "W00356", "name": "Đặng Quốc Phương", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "GPDN, Boss", "note": ""}, {"id": "Prod 2_109_W00357", "stt": 109, "code": "W00357", "name": "Nguyễn Thanh Bình", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Broach, Hob", "note": ""}, {"id": "Prod 2_110_W00358", "stt": 110, "code": "W00358", "name": "Nguyễn Thanh Tâm", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Shaving, Shaper", "note": ""}, {"id": "Prod 2_111_W00359", "stt": 111, "code": "W00359", "name": "Nguyễn Bá Tâm", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Broach, Hob", "note": ""}, {"id": "Prod 2_112_W00360", "stt": 112, "code": "W00360", "name": "Hà Văn Lợi", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "GPDN, Boss", "note": ""}, {"id": "Prod 2_113_W00361", "stt": 113, "code": "W00361", "name": "Phạm Thế Chuyền", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "GPDN, Boss", "note": ""}, {"id": "Prod 2_114_W00364", "stt": 114, "code": "W00364", "name": "Bùi Ngọc Dương", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Axle", "note": ""}, {"id": "Prod 2_115_W00383", "stt": 115, "code": "W00383", "name": "Ngô Uân Tuân", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Shaving, Shaper", "note": ""}, {"id": "Prod 2_116_W00392", "stt": 116, "code": "W00392", "name": "Nguyễn Thành Nam", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Gear Senban", "note": ""}, {"id": "Prod 2_117_W00397", "stt": 117, "code": "W00397", "name": "Nguyễn Thị Hồng Vân", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Broach, Hob", "note": ""}, {"id": "Prod 2_118_W00436", "stt": 118, "code": "W00436", "name": "Nguyễn Thành Đô", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Gear Senban", "note": ""}, {"id": "Prod 2_119_W00443", "stt": 119, "code": "W00443", "name": "Thịnh Văn Tuyên", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "GPDN, Boss", "note": ""}, {"id": "Prod 2_120_W00456", "stt": 120, "code": "W00456", "name": "Đổng Thị Thà", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "GPDN, Boss", "note": ""}, {"id": "Prod 2_121_W00511", "stt": 121, "code": "W00511", "name": "Nguyễn Hữu Dương", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "GPDN, Boss", "note": ""}, {"id": "Prod 2_122_W00617", "stt": 122, "code": "W00617", "name": "Nguyễn Xuân Thảo", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "GPDN, Boss", "note": ""}, {"id": "Prod 2_123_W00725", "stt": 123, "code": "W00725", "name": "Nguyễn Văn Linh", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "GPDN, Boss", "note": ""}, {"id": "Prod 2_124_W00737", "stt": 124, "code": "W00737", "name": "Lê Quang Dũng", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Gear Senban", "note": ""}, {"id": "Prod 2_125_W00785", "stt": 125, "code": "W00785", "name": "Nguyễn Văn Đại", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Broach, Hob", "note": ""}, {"id": "Prod 2_126_W00888", "stt": 126, "code": "W00888", "name": "Nguyễn Quang Mạnh", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Broach, Hob", "note": ""}, {"id": "Prod 2_127_W00920", "stt": 127, "code": "W00920", "name": "Nguyễn Văn Dương", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Axle", "note": ""}, {"id": "Prod 2_128_W00927", "stt": 128, "code": "W00927", "name": "Dương Thị Hà", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Axle", "note": ""}, {"id": "Prod 2_129_W00928", "stt": 129, "code": "W00928", "name": "Trịnh Thị Thu Hà", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Gear Senban", "note": ""}, {"id": "Prod 2_130_W00936", "stt": 130, "code": "W00936", "name": "Nguyễn Thị Hoà", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "GPDN, Boss", "note": ""}, {"id": "Prod 2_131_W00976", "stt": 131, "code": "W00976", "name": "Nguyễn Trí Thanh", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Broach, Hob", "note": ""}, {"id": "Prod 2_132_W00986", "stt": 132, "code": "W00986", "name": "Nguyễn Quyết Tiến", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Broach, Hob", "note": ""}, {"id": "Prod 2_133_W01115", "stt": 133, "code": "W01115", "name": "Dương Thị Diện", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Axle", "note": ""}, {"id": "Prod 2_134_W01117", "stt": 134, "code": "W01117", "name": "Trần Thị Hoa Trang", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Gear Senban", "note": ""}, {"id": "Prod 2_135_W01160", "stt": 135, "code": "W01160", "name": "Hoàng Văn Thường", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Broach, Hob", "note": ""}, {"id": "Prod 2_136_W01229", "stt": 136, "code": "W01229", "name": "Lê Văn Lợi", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Shaving, Shaper", "note": ""}, {"id": "Prod 2_137_W01336", "stt": 137, "code": "W01336", "name": "Đoàn Đức Dũng", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Gear Senban", "note": ""}, {"id": "Prod 2_138_W01505", "stt": 138, "code": "W01505", "name": "Cù Tiến Chúc", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Gear Senban", "note": ""}, {"id": "Prod 2_139_W01513", "stt": 139, "code": "W01513", "name": "Đào Văn Hải", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Gear Senban", "note": ""}, {"id": "Prod 2_140_W01519", "stt": 140, "code": "W01519", "name": "Ngô Khắc Huệ", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "GPDN, Boss", "note": ""}, {"id": "Prod 2_141_W01540", "stt": 141, "code": "W01540", "name": "Nguyễn Văn Ngọc", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "GPDN, Boss", "note": ""}, {"id": "Prod 2_142_W01545", "stt": 142, "code": "W01545", "name": "Nguyễn Gia Quỳnh", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Axle", "note": ""}, {"id": "Prod 2_143_W01618", "stt": 143, "code": "W01618", "name": "Trần Văn Huân", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Gear Senban", "note": ""}, {"id": "Prod 2_144_W01702", "stt": 144, "code": "W01702", "name": "Trần Văn Dũng", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Broach, Hob", "note": ""}, {"id": "Prod 2_145_W01740", "stt": 145, "code": "W01740", "name": "Trần Văn Hùng", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "GPDN, Boss", "note": ""}, {"id": "Prod 2_146_W01774", "stt": 146, "code": "W01774", "name": "Lê Văn Thực", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Gear Senban", "note": ""}, {"id": "Prod 2_147_W01784", "stt": 147, "code": "W01784", "name": "Đỗ Thị ánh", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Axle", "note": ""}, {"id": "Prod 2_148_W01793", "stt": 148, "code": "W01793", "name": "Nguyễn Thị Loan", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "GPDN, Boss", "note": ""}, {"id": "Prod 2_149_W01806", "stt": 149, "code": "W01806", "name": "Hoàng Thị Phượng", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Broach, Hob", "note": ""}, {"id": "Prod 2_150_W01823", "stt": 150, "code": "W01823", "name": "Lưu Thị Hường", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Axle", "note": ""}, {"id": "Prod 2_151_W01836", "stt": 151, "code": "W01836", "name": "Nguyễn Thị Phượng", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Broach, Hob", "note": ""}, {"id": "Prod 2_152_W01847", "stt": 152, "code": "W01847", "name": "Nguyễn Thị Tình", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Gear Senban", "note": ""}, {"id": "Prod 2_153_W01851", "stt": 153, "code": "W01851", "name": "Trần Thị Thùy", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Shaving, Shaper", "note": ""}, {"id": "Prod 2_154_W01890", "stt": 154, "code": "W01890", "name": "Nghiêm Đình Quý", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Axle", "note": ""}, {"id": "Prod 2_155_W01894", "stt": 155, "code": "W01894", "name": "Vũ Văn Tuấn", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Gear Senban", "note": ""}, {"id": "Prod 2_156_W01907", "stt": 156, "code": "W01907", "name": "Dương Văn Tú", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Gear Senban", "note": ""}, {"id": "Prod 2_157_W01921", "stt": 157, "code": "W01921", "name": "Phạm Văn Dũng", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Broach, Hob", "note": ""}, {"id": "Prod 2_158_W01940", "stt": 158, "code": "W01940", "name": "Nguyễn Xuân Thơm", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "GPDN, Boss", "note": ""}, {"id": "Prod 2_159_W01945", "stt": 159, "code": "W01945", "name": "Hà Văn Xuân", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Shaving, Shaper", "note": ""}, {"id": "Prod 2_160_W01950", "stt": 160, "code": "W01950", "name": "Nguyễn Công Long", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Gear Senban", "note": ""}, {"id": "Prod 2_161_W02019", "stt": 161, "code": "W02019", "name": "Trần Thị Loan", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "GPDN, Boss", "note": ""}, {"id": "Prod 2_162_W02028", "stt": 162, "code": "W02028", "name": "Nguyễn Thị Bích Phượng", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Shaving, Shaper", "note": ""}, {"id": "Prod 2_163_W02318", "stt": 163, "code": "W02318", "name": "Âu Văn Thìn", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Gear Senban", "note": ""}, {"id": "Prod 2_164_W02398", "stt": 164, "code": "W02398", "name": "Nguyễn Thị Thủy", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Broach, Hob", "note": ""}, {"id": "Prod 2_165_W02407", "stt": 165, "code": "W02407", "name": "Nguyễn Thị Én", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Shaving, Shaper", "note": ""}, {"id": "Prod 2_166_W02456", "stt": 166, "code": "W02456", "name": "Trần Văn Ninh", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Gear Senban", "note": ""}, {"id": "Prod 2_167_W02496", "stt": 167, "code": "W02496", "name": "Nguyễn Việt Thắng", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Broach, Hob", "note": ""}, {"id": "Prod 2_168_W02567", "stt": 168, "code": "W02567", "name": "Nguyễn Văn Khánh", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Axle", "note": ""}, {"id": "Prod 2_169_W02647", "stt": 169, "code": "W02647", "name": "Vũ Văn Hoàn", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Gear Senban", "note": ""}, {"id": "Prod 2_170_W02744", "stt": 170, "code": "W02744", "name": "Nguyễn Thị Mai", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Broach, Hob", "note": ""}, {"id": "Prod 2_171_W02760", "stt": 171, "code": "W02760", "name": "Đào Xuân Lơ", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Gear Senban", "note": ""}, {"id": "Prod 2_172_W02817", "stt": 172, "code": "W02817", "name": "Nguyễn Thị Mùi", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Gear Senban", "note": ""}, {"id": "Prod 2_173_W02818", "stt": 173, "code": "W02818", "name": "Đồng Thị Nhung", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "GPDN, Boss", "note": ""}, {"id": "Prod 2_174_W03046", "stt": 174, "code": "W03046", "name": "Dương Văn Dịnh", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "GPDN, Boss", "note": ""}, {"id": "Prod 2_175_W03112", "stt": 175, "code": "W03112", "name": "Nguyễn Trung Sơn", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "GPDN, Boss", "note": ""}, {"id": "Prod 2_176_W03116", "stt": 176, "code": "W03116", "name": "Nguyễn Đại Trượng", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Axle", "note": ""}, {"id": "Prod 2_177_W03144", "stt": 177, "code": "W03144", "name": "Đỗ Thị Phú", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Shaving, Shaper", "note": ""}, {"id": "Prod 2_178_W03308", "stt": 178, "code": "W03308", "name": "Nguyễn Thị Linh", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Shaving, Shaper", "note": ""}, {"id": "Prod 2_179_W03345", "stt": 179, "code": "W03345", "name": "Đặng Thành Dân", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Gear Senban", "note": ""}, {"id": "Prod 2_180_W03348", "stt": 180, "code": "W03348", "name": "Phạm Văn Lưu", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Broach, Hob", "note": ""}, {"id": "Prod 2_181_W03468", "stt": 181, "code": "W03468", "name": "Trần Thị Hoàn", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Gear Senban", "note": ""}, {"id": "Prod 2_182_W03469", "stt": 182, "code": "W03469", "name": "Ngô Thị Hương Ly", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Gear Senban", "note": ""}, {"id": "Prod 2_183_W03474", "stt": 183, "code": "W03474", "name": "Bàn Thị Phượng", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Axle", "note": ""}, {"id": "Prod 2_184_W03475", "stt": 184, "code": "W03475", "name": "Nguyễn Thị Nhiên", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Gear Senban", "note": ""}, {"id": "Prod 2_185_W03481", "stt": 185, "code": "W03481", "name": "Đào Thị Mai", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Gear Senban", "note": ""}, {"id": "Prod 2_186_W03602", "stt": 186, "code": "W03602", "name": "Bàn Văn Vấn", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Broach, Hob", "note": ""}, {"id": "Prod 2_187_W03703", "stt": 187, "code": "W03703", "name": "Phạm Thị Hòa", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Gear Senban", "note": ""}, {"id": "Prod 2_188_W03713", "stt": 188, "code": "W03713", "name": "Hoàng Thị Thu Hiền", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Gear Senban", "note": ""}, {"id": "Prod 2_189_W03724", "stt": 189, "code": "W03724", "name": "Đặng Thị Minh Thỏa", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Gear Senban", "note": ""}, {"id": "Prod 2_190_W03754", "stt": 190, "code": "W03754", "name": "Bùi Văn Tài", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "GPDN, Boss", "note": ""}, {"id": "Prod 2_191_W03870", "stt": 191, "code": "W03870", "name": "Nguyễn Đức Toàn", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Axle", "note": ""}, {"id": "Prod 2_192_W03882", "stt": 192, "code": "W03882", "name": "Phạm Thị Hường", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Gear Senban", "note": ""}, {"id": "Prod 2_193_W03902", "stt": 193, "code": "W03902", "name": "Trần Thị Thanh Hương", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Shaving, Shaper", "note": ""}, {"id": "Prod 2_194_W04014", "stt": 194, "code": "W04014", "name": "Đỗ Thị Hát", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Gear Senban", "note": ""}, {"id": "Prod 2_195_W04070", "stt": 195, "code": "W04070", "name": "Nguyễn Việt Dũng", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Gear Senban", "note": ""}, {"id": "Prod 2_196_W04255", "stt": 196, "code": "W04255", "name": "Đỗ Thị Tâm", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Axle", "note": ""}, {"id": "Prod 2_197_W04256", "stt": 197, "code": "W04256", "name": "Nguyễn Thị Hạnh", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "GPDN, Boss", "note": ""}, {"id": "Prod 2_198_W04269", "stt": 198, "code": "W04269", "name": "Đào Thị Thúy Hà", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Shaving, Shaper", "note": ""}, {"id": "Prod 2_199_W04286", "stt": 199, "code": "W04286", "name": "Nguyễn Văn Thủy", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "GPDN, Boss", "note": ""}, {"id": "Prod 2_200_W04384", "stt": 200, "code": "W04384", "name": "Trần Thị Chuyên", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Broach, Hob", "note": ""}, {"id": "Prod 2_201_W04551", "stt": 201, "code": "W04551", "name": "Nguyễn Văn Hùng", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Gear Senban", "note": ""}, {"id": "Prod 2_202_W04589", "stt": 202, "code": "W04589", "name": "Lê Thị Huyên", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Axle", "note": ""}, {"id": "Prod 2_203_W04641", "stt": 203, "code": "W04641", "name": "Trương Mạnh Hải", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Shaving, Shaper", "note": ""}, {"id": "Prod 2_204_W04726", "stt": 204, "code": "W04726", "name": "Đường Thị Thìn", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Gear Senban", "note": ""}, {"id": "Prod 2_205_W04761", "stt": 205, "code": "W04761", "name": "Nguyễn Duy Năng", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Gear Senban", "note": ""}, {"id": "Prod 2_206_W04783", "stt": 206, "code": "W04783", "name": "Nông Văn Tường", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Gear Senban", "note": ""}, {"id": "Prod 2_207_W04813", "stt": 207, "code": "W04813", "name": "Đặng Quốc Chính", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "GPDN, Boss", "note": ""}, {"id": "Prod 2_208_W04878", "stt": 208, "code": "W04878", "name": "Nguyễn Văn Trường", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "GPDN, Boss", "note": ""}, {"id": "Prod 2_209_W04958", "stt": 209, "code": "W04958", "name": "Hoàng Vinh Bích", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "GPDN, Boss", "note": ""}, {"id": "Prod 2_210_W05053", "stt": 210, "code": "W05053", "name": "Đàm Văn Đức", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Axle", "note": ""}, {"id": "Prod 2_211_W05057", "stt": 211, "code": "W05057", "name": "Nguyễn Văn Toán", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Gear Senban", "note": ""}, {"id": "Prod 2_212_W05067", "stt": 212, "code": "W05067", "name": "Đào Thị Miên", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Gear Senban", "note": ""}, {"id": "Prod 2_213_W05079", "stt": 213, "code": "W05079", "name": "Nguyễn Thị Thu", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Gear Senban", "note": ""}, {"id": "Prod 2_214_W05087", "stt": 214, "code": "W05087", "name": "Nguyễn Hữu Long", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Broach, Hob", "note": ""}, {"id": "Prod 2_215_W05162", "stt": 215, "code": "W05162", "name": "Nguyễn Duy Trường", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Broach, Hob", "note": ""}, {"id": "Prod 2_216_W05171", "stt": 216, "code": "W05171", "name": "Trần Văn Vinh", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Axle", "note": ""}, {"id": "Prod 2_217_W05177", "stt": 217, "code": "W05177", "name": "Nguyễn Thế Bình", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Broach, Hob", "note": ""}, {"id": "Prod 2_218_W05187", "stt": 218, "code": "W05187", "name": "Vương Xuân Đích", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Gear Senban", "note": ""}, {"id": "Prod 2_219_W05229", "stt": 219, "code": "W05229", "name": "Vũ Văn Thọ", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Axle", "note": ""}, {"id": "Prod 2_220_W05243", "stt": 220, "code": "W05243", "name": "Nguyễn Doãn Tùng", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Axle", "note": ""}, {"id": "Prod 2_221_W05275", "stt": 221, "code": "W05275", "name": "Nguyễn Danh Biên", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Gear Senban", "note": ""}, {"id": "Prod 2_222_W05294", "stt": 222, "code": "W05294", "name": "Nguyễn Danh Hưng", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Broach, Hob", "note": ""}, {"id": "Prod 2_223_W05323", "stt": 223, "code": "W05323", "name": "Nguyễn Anh Tuyển", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Broach, Hob", "note": ""}, {"id": "Prod 2_224_W05363", "stt": 224, "code": "W05363", "name": "Trần Đức Giang", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Broach, Hob", "note": ""}, {"id": "Prod 2_225_W05368", "stt": 225, "code": "W05368", "name": "Nguyễn Danh Khương", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Gear Senban", "note": ""}, {"id": "Prod 2_226_W05374", "stt": 226, "code": "W05374", "name": "Nguyễn Thế Việt", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Gear Senban", "note": ""}, {"id": "Prod 2_227_W05376", "stt": 227, "code": "W05376", "name": "Thang Thị Chiên", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Broach, Hob", "note": ""}, {"id": "Prod 2_228_W05379", "stt": 228, "code": "W05379", "name": "Ngô Đắc Hậu", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Broach, Hob", "note": ""}, {"id": "Prod 2_229_W05388", "stt": 229, "code": "W05388", "name": "Đỗ Thị Hương Quỳnh", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Axle", "note": ""}, {"id": "Prod 2_230_W05481", "stt": 230, "code": "W05481", "name": "Quách Xuân Tịnh", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Axle", "note": ""}, {"id": "Prod 2_231_W05486", "stt": 231, "code": "W05486", "name": "Nguyễn Thị Dung", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Gear Senban", "note": ""}, {"id": "Prod 2_232_W05489", "stt": 232, "code": "W05489", "name": "Đỗ Thị Oanh", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Gear Senban", "note": ""}, {"id": "Prod 2_233_W05502", "stt": 233, "code": "W05502", "name": "Nguyễn Thị Thanh", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Gear Senban", "note": ""}, {"id": "Prod 2_234_W05504", "stt": 234, "code": "W05504", "name": "Nguyễn Văn Tùng", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Broach, Hob", "note": ""}, {"id": "Prod 2_235_W05511", "stt": 235, "code": "W05511", "name": "Phạm Văn Cường", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Axle", "note": ""}, {"id": "Prod 2_236_W05536", "stt": 236, "code": "W05536", "name": "Nguyễn Hữu Bảo", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Broach, Hob", "note": ""}, {"id": "Prod 2_237_W05543", "stt": 237, "code": "W05543", "name": "Nguyễn Đức Kiên", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Gear Senban", "note": ""}, {"id": "Prod 2_238_W05589", "stt": 238, "code": "W05589", "name": "Đồng Văn Cường", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Gear Senban", "note": ""}, {"id": "Prod 2_239_W05599", "stt": 239, "code": "W05599", "name": "Lê Thị Hồng Sâm", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "GPDN, Boss", "note": ""}, {"id": "Prod 2_240_W05603", "stt": 240, "code": "W05603", "name": "Ngô Thị Hồng", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "GPDN, Boss", "note": ""}, {"id": "Prod 2_241_W05607", "stt": 241, "code": "W05607", "name": "Nguyễn Đăng Giáp", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "GPDN, Boss", "note": ""}, {"id": "Prod 2_242_W05611", "stt": 242, "code": "W05611", "name": "Nguyễn Thị Hiền", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Gear Senban", "note": ""}, {"id": "Prod 2_243_W05612", "stt": 243, "code": "W05612", "name": "Nguyễn Thị Hưng", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Axle", "note": ""}, {"id": "Prod 2_244_W05613", "stt": 244, "code": "W05613", "name": "Nguyễn Thị Hường", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "GPDN, Boss", "note": ""}, {"id": "Prod 2_245_W05617", "stt": 245, "code": "W05617", "name": "Nguyễn Thị Thịnh", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Gear Senban", "note": ""}, {"id": "Prod 2_246_W05618", "stt": 246, "code": "W05618", "name": "Nguyễn Thị Thu Dung", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Gear Senban", "note": ""}, {"id": "Prod 2_247_W05621", "stt": 247, "code": "W05621", "name": "Nguyễn Văn Đồng", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Axle", "note": ""}, {"id": "Prod 2_248_W05622", "stt": 248, "code": "W05622", "name": "Nguyễn Văn Đức", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Axle", "note": ""}, {"id": "Prod 2_249_W05623", "stt": 249, "code": "W05623", "name": "Nguyễn Văn Dũng", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Axle", "note": ""}, {"id": "Prod 2_250_W05631", "stt": 250, "code": "W05631", "name": "Nguyễn Văn Sinh", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Broach, Hob", "note": ""}, {"id": "Prod 2_251_W05632", "stt": 251, "code": "W05632", "name": "Nguyễn Văn Thắng", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Broach, Hob", "note": ""}, {"id": "Prod 2_252_W05634", "stt": 252, "code": "W05634", "name": "Hoàng Thị Bích Hiền", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Shaving, Shaper", "note": ""}, {"id": "Prod 2_253_W05637", "stt": 253, "code": "W05637", "name": "Nguyễn Thị Lụa", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Gear Senban", "note": ""}, {"id": "Prod 2_254_W05638", "stt": 254, "code": "W05638", "name": "Cù Xuân Sơn", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Broach, Hob", "note": ""}, {"id": "Prod 2_255_W05643", "stt": 255, "code": "W05643", "name": "Nguyễn Bình Thành", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Gear Senban", "note": ""}, {"id": "Prod 2_256_W05645", "stt": 256, "code": "W05645", "name": "Trần Văn Quyết", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Broach, Hob", "note": ""}, {"id": "Prod 2_257_W05646", "stt": 257, "code": "W05646", "name": "Vũ Mạnh Hùng", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Broach, Hob", "note": ""}, {"id": "Prod 2_258_W05650", "stt": 258, "code": "W05650", "name": "Đặng Thị Thu Mai", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "GPDN, Boss", "note": ""}, {"id": "Prod 2_259_W05654", "stt": 259, "code": "W05654", "name": "Đỗ Văn Khiêm", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Gear Senban", "note": ""}, {"id": "Prod 2_260_W05662", "stt": 260, "code": "W05662", "name": "Nguyễn Hải Quân", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Shaving, Shaper", "note": ""}, {"id": "Prod 2_261_W05663", "stt": 261, "code": "W05663", "name": "Nguyễn Tiến Dũng", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Broach, Hob", "note": ""}, {"id": "Prod 2_262_W05665", "stt": 262, "code": "W05665", "name": "Nguyễn Văn Hùng", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Shaving, Shaper", "note": ""}, {"id": "Prod 2_263_W05666", "stt": 263, "code": "W05666", "name": "Nguyễn Xuân Thắng", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Gear Senban", "note": ""}, {"id": "Prod 2_264_W05668", "stt": 264, "code": "W05668", "name": "Nguyễn Duy Đức", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Axle", "note": ""}, {"id": "Prod 2_265_W05673", "stt": 265, "code": "W05673", "name": "Nguyễn Thị Thu Hà", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "GPDN, Boss", "note": ""}, {"id": "Prod 2_266_W05707", "stt": 266, "code": "W05707", "name": "Đào Thị Thơm", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Axle", "note": ""}, {"id": "Prod 2_267_W05710", "stt": 267, "code": "W05710", "name": "Nguyễn Thị Ngà", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "GPDN, Boss", "note": ""}, {"id": "Prod 2_268_W05718", "stt": 268, "code": "W05718", "name": "Đào Thanh Tú", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Broach, Hob", "note": ""}, {"id": "Prod 2_269_W05732", "stt": 269, "code": "W05732", "name": "Nguyễn Mạnh Thắng", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "GPDN, Boss", "note": ""}, {"id": "Prod 2_270_W05738", "stt": 270, "code": "W05738", "name": "Nguyễn Văn Đức", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Axle", "note": ""}, {"id": "Prod 2_271_W05746", "stt": 271, "code": "W05746", "name": "Nguyễn Văn Thắng", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Axle", "note": ""}, {"id": "Prod 2_272_W05755", "stt": 272, "code": "W05755", "name": "Nguyễn Quang Bắc", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Gear Senban", "note": ""}, {"id": "Prod 2_273_W05764", "stt": 273, "code": "W05764", "name": "Nguyễn Văn Hiến", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Broach, Hob", "note": ""}, {"id": "Prod 2_274_W05776", "stt": 274, "code": "W05776", "name": "Trần Văn Sơn", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Gear Senban", "note": ""}, {"id": "Prod 2_275_W05793", "stt": 275, "code": "W05793", "name": "Hoàng Thị Quỳnh", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Axle", "note": ""}, {"id": "Prod 2_276_W05798", "stt": 276, "code": "W05798", "name": "Đồng Thị Hải", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Axle", "note": ""}, {"id": "Prod 2_277_W05799", "stt": 277, "code": "W05799", "name": "Nguyễn Thị Sinh", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Broach, Hob", "note": ""}, {"id": "Prod 2_278_W05801", "stt": 278, "code": "W05801", "name": "Trần Thị Phương", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Shaving, Shaper", "note": ""}, {"id": "Prod 2_279_W05816", "stt": 279, "code": "W05816", "name": "Vũ Văn Văn", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Gear Senban", "note": ""}, {"id": "Prod 2_280_W05819", "stt": 280, "code": "W05819", "name": "Ngô Văn Thu", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Gear Senban", "note": ""}, {"id": "Prod 2_281_W05822", "stt": 281, "code": "W05822", "name": "Lã Văn Tiên", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Broach, Hob", "note": ""}, {"id": "Prod 2_282_W05824", "stt": 282, "code": "W05824", "name": "Nguyễn Thị Phương", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Broach, Hob", "note": ""}, {"id": "Prod 2_283_W05829", "stt": 283, "code": "W05829", "name": "Đỗ Thị Mai", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Gear Senban", "note": ""}, {"id": "Prod 2_284_W05844", "stt": 284, "code": "W05844", "name": "Vũ Bá Tráng", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Broach, Hob", "note": ""}, {"id": "Prod 2_285_W05874", "stt": 285, "code": "W05874", "name": "Trần Thị Dáng", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Gear Senban", "note": ""}, {"id": "Prod 2_286_W05875", "stt": 286, "code": "W05875", "name": "Lê Thị Lương", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Gear Senban", "note": ""}, {"id": "Prod 2_287_W05878", "stt": 287, "code": "W05878", "name": "Hà Thị Tuyết", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Broach, Hob", "note": ""}, {"id": "Prod 2_288_W05881", "stt": 288, "code": "W05881", "name": "Nguyễn Thị Hà", "dept": "Prod 2", "department": "Production 2", "shop": "Before Heat treatment", "group": "Shaving, Shaper", "note": ""}, {"id": "Prod 2_289_W00110", "stt": 289, "code": "W00110", "name": "Bùi Thị Hạnh", "dept": "Prod 2", "department": "Production 2", "shop": "Cleaning Basket", "group": "", "note": ""}, {"id": "Prod 2_290_W00332", "stt": 290, "code": "W00332", "name": "Nguyễn Văn Tâm", "dept": "Prod 2", "department": "Production 2", "shop": "Cleaning Basket", "group": "", "note": ""}, {"id": "Prod 2_291_W00415", "stt": 291, "code": "W00415", "name": "Trương Văn Dương", "dept": "Prod 2", "department": "Production 2", "shop": "Cleaning Basket", "group": "", "note": ""}, {"id": "Prod 2_292_W00486", "stt": 292, "code": "W00486", "name": "Đặng Mạnh Bính", "dept": "Prod 2", "department": "Production 2", "shop": "Cleaning Basket", "group": "", "note": ""}, {"id": "Prod 2_293_W00993", "stt": 293, "code": "W00993", "name": "Nguyễn Thị Thúy Tính", "dept": "Prod 2", "department": "Production 2", "shop": "Cleaning Basket", "group": "", "note": ""}, {"id": "Prod 2_294_W01268", "stt": 294, "code": "W01268", "name": "Nguyễn Thị Lan Hương", "dept": "Prod 2", "department": "Production 2", "shop": "Cleaning Basket", "group": "", "note": ""}, {"id": "Prod 2_295_W02024", "stt": 295, "code": "W02024", "name": "Trần Thị Lan", "dept": "Prod 2", "department": "Production 2", "shop": "Cleaning Basket", "group": "", "note": ""}, {"id": "Prod 2_296_W03387", "stt": 296, "code": "W03387", "name": "Đoàn Văn Định", "dept": "Prod 2", "department": "Production 2", "shop": "Cleaning Basket", "group": "", "note": ""}, {"id": "Prod 2_297_W05393", "stt": 297, "code": "W05393", "name": "Trần Văn Thắng", "dept": "Prod 2", "department": "Production 2", "shop": "Cleaning Basket", "group": "", "note": ""}, {"id": "Prod 2_298_W05596", "stt": 298, "code": "W05596", "name": "Lại Thế Ngọc", "dept": "Prod 2", "department": "Production 2", "shop": "Cleaning Basket", "group": "", "note": ""}, {"id": "Prod 2_299_W05624", "stt": 299, "code": "W05624", "name": "Nguyễn Văn Dũng", "dept": "Prod 2", "department": "Production 2", "shop": "Cleaning Basket", "group": "", "note": ""}, {"id": "Prod 2_300_W05873", "stt": 300, "code": "W05873", "name": "Nguyễn Thị Thanh", "dept": "Prod 2", "department": "Production 2", "shop": "Cleaning Basket", "group": "", "note": ""}, {"id": "Prod 2_301_W00119", "stt": 301, "code": "W00119", "name": "Nguyễn Mậu Hưng", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Dies making", "note": ""}, {"id": "Prod 2_302_W00124", "stt": 302, "code": "W00124", "name": "Nguyễn Việt Long", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Hot press", "note": ""}, {"id": "Prod 2_303_W00212", "stt": 303, "code": "W00212", "name": "Nguyễn Văn Cường", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Dies setting", "note": ""}, {"id": "Prod 2_304_W00248", "stt": 304, "code": "W00248", "name": "Nguyễn Quang Triều", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Dies making", "note": ""}, {"id": "Prod 2_305_W00355", "stt": 305, "code": "W00355", "name": "Nguyễn Anh Đại", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Axle Press", "note": ""}, {"id": "Prod 2_306_W00379", "stt": 306, "code": "W00379", "name": "Lê Thanh Sơn", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Dies making", "note": ""}, {"id": "Prod 2_307_W00469", "stt": 307, "code": "W00469", "name": "Lê Thị Thuý", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Dies making", "note": ""}, {"id": "Prod 2_308_W00501", "stt": 308, "code": "W00501", "name": "Lê Minh Hiếu", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Cold Press", "note": ""}, {"id": "Prod 2_309_W00609", "stt": 309, "code": "W00609", "name": "Nguyễn Văn Thành", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Dies setting", "note": ""}, {"id": "Prod 2_310_W00674", "stt": 310, "code": "W00674", "name": "Nguyễn Huy Duy", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Axle Press", "note": ""}, {"id": "Prod 2_311_W00752", "stt": 311, "code": "W00752", "name": "Ma Văn Tuyên", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Axle Press", "note": ""}, {"id": "Prod 2_312_W00859", "stt": 312, "code": "W00859", "name": "Tạ Văn Tiệp", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Dies making", "note": ""}, {"id": "Prod 2_313_W00943", "stt": 313, "code": "W00943", "name": "Nguyễn Trường Lâm", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Hot press", "note": ""}, {"id": "Prod 2_314_W00988", "stt": 314, "code": "W00988", "name": "Trần Kim Trung", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Hot press", "note": ""}, {"id": "Prod 2_315_W01128", "stt": 315, "code": "W01128", "name": "Nguyễn Xuân Hiền", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Ann, Shot, Bonde", "note": ""}, {"id": "Prod 2_316_W01499", "stt": 316, "code": "W01499", "name": "Đặng Trọng Trường", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Sawing + Shearing", "note": ""}, {"id": "Prod 2_317_W01739", "stt": 317, "code": "W01739", "name": "Phan Duy Hùng", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Ann, Shot, Bonde", "note": ""}, {"id": "Prod 2_318_W01908", "stt": 318, "code": "W01908", "name": "Nguyễn Minh Tuấn", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Cold Press", "note": ""}, {"id": "Prod 2_319_W01942", "stt": 319, "code": "W01942", "name": "Nguyễn Văn Hùng", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Trimming", "note": ""}, {"id": "Prod 2_320_W02224", "stt": 320, "code": "W02224", "name": "Nguyễn Văn Vương", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Cold Press", "note": ""}, {"id": "Prod 2_321_W02411", "stt": 321, "code": "W02411", "name": "Nguyễn Thị Dự", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Dies making", "note": ""}, {"id": "Prod 2_322_W02455", "stt": 322, "code": "W02455", "name": "Ma Văn Toàn", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Hot press", "note": ""}, {"id": "Prod 2_323_W02476", "stt": 323, "code": "W02476", "name": "Tô Thành Nguyên", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Axle Press", "note": ""}, {"id": "Prod 2_324_W02560", "stt": 324, "code": "W02560", "name": "Nguyễn Văn Hòa", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Dies making", "note": ""}, {"id": "Prod 2_325_W02620", "stt": 325, "code": "W02620", "name": "Lại Thị Hiền Lương", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Dies making", "note": ""}, {"id": "Prod 2_326_W02637", "stt": 326, "code": "W02637", "name": "Nguyễn Duy Hùng", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Hot press", "note": ""}, {"id": "Prod 2_327_W03363", "stt": 327, "code": "W03363", "name": "Nguyễn Văn Quân", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Sawing + Shearing", "note": ""}, {"id": "Prod 2_328_W03663", "stt": 328, "code": "W03663", "name": "Nguyễn Bá Phúc", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Hot press", "note": ""}, {"id": "Prod 2_329_W03735", "stt": 329, "code": "W03735", "name": "Lê Tất Duẩn", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Ann, Shot, Bonde", "note": ""}, {"id": "Prod 2_330_W03838", "stt": 330, "code": "W03838", "name": "Hoàng Xuân Mạnh", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Sawing + Shearing", "note": ""}, {"id": "Prod 2_331_W03858", "stt": 331, "code": "W03858", "name": "Cao Quốc Khánh", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Dies setting", "note": ""}, {"id": "Prod 2_332_W04021", "stt": 332, "code": "W04021", "name": "Hoàng Văn Ngọc", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Axle Press", "note": ""}, {"id": "Prod 2_333_W04214", "stt": 333, "code": "W04214", "name": "Vũ Công Hoan", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Axle Press", "note": ""}, {"id": "Prod 2_334_W04353", "stt": 334, "code": "W04353", "name": "Nguyễn Công Thức", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Trimming", "note": ""}, {"id": "Prod 2_335_W04379", "stt": 335, "code": "W04379", "name": "Hoàng Văn Hùng", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Hot press", "note": ""}, {"id": "Prod 2_336_W04743", "stt": 336, "code": "W04743", "name": "Đỗ Đăng Dương", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Dies setting", "note": ""}, {"id": "Prod 2_337_W04835", "stt": 337, "code": "W04835", "name": "Đỗ Đăng Hoàn", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Hot press", "note": ""}, {"id": "Prod 2_338_W05109", "stt": 338, "code": "W05109", "name": "Đào Văn Dũng", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Trimming", "note": ""}, {"id": "Prod 2_339_W05131", "stt": 339, "code": "W05131", "name": "Nguyễn Văn Minh", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Cold Press", "note": ""}, {"id": "Prod 2_340_W05139", "stt": 340, "code": "W05139", "name": "Nguyễn Danh Phong", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Dies making", "note": ""}, {"id": "Prod 2_341_W05158", "stt": 341, "code": "W05158", "name": "Nguyễn Danh Toàn", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Hot press", "note": ""}, {"id": "Prod 2_342_W05165", "stt": 342, "code": "W05165", "name": "Nguyễn Văn Tuấn", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Cold Press", "note": ""}, {"id": "Prod 2_343_W05239", "stt": 343, "code": "W05239", "name": "Nguyễn Minh Tú", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Cold Press", "note": ""}, {"id": "Prod 2_344_W05289", "stt": 344, "code": "W05289", "name": "Nguyễn Văn Hòa", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Hot press", "note": ""}, {"id": "Prod 2_345_W05387", "stt": 345, "code": "W05387", "name": "Nguyễn Thành Quân", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Hot press", "note": ""}, {"id": "Prod 2_346_W05394", "stt": 346, "code": "W05394", "name": "Hoàng Chí Thanh", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Hot press", "note": ""}, {"id": "Prod 2_347_W05439", "stt": 347, "code": "W05439", "name": "Ngô Mạnh Hoàng", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Axle Press", "note": ""}, {"id": "Prod 2_348_W05498", "stt": 348, "code": "W05498", "name": "Đỗ Đăng Chiến", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Cold Press", "note": ""}, {"id": "Prod 2_349_W05525", "stt": 349, "code": "W05525", "name": "Trần Đăng Khoa", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Axle Press", "note": ""}, {"id": "Prod 2_350_W05584", "stt": 350, "code": "W05584", "name": "Đinh Công Ninh", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Sawing + Shearing", "note": ""}, {"id": "Prod 2_351_W05587", "stt": 351, "code": "W05587", "name": "Đỗ Văn Mạnh", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Axle Press", "note": ""}, {"id": "Prod 2_352_W05590", "stt": 352, "code": "W05590", "name": "Đồng Xuân Sơn", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Hot press", "note": ""}, {"id": "Prod 2_353_W05591", "stt": 353, "code": "W05591", "name": "Dương Ngọc Đoan", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Sawing + Shearing", "note": ""}, {"id": "Prod 2_354_W05593", "stt": 354, "code": "W05593", "name": "Hoàng Anh Tuấn", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Cold Press", "note": ""}, {"id": "Prod 2_355_W05595", "stt": 355, "code": "W05595", "name": "La Văn Hải", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Hot press", "note": ""}, {"id": "Prod 2_356_W05597", "stt": 356, "code": "W05597", "name": "Lê Đắc Tuấn", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Hot press", "note": ""}, {"id": "Prod 2_357_W05598", "stt": 357, "code": "W05598", "name": "Lê Đình Luân", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Hot press", "note": ""}, {"id": "Prod 2_358_W05601", "stt": 358, "code": "W05601", "name": "Lê Văn Tuấn", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Hot press", "note": ""}, {"id": "Prod 2_359_W05605", "stt": 359, "code": "W05605", "name": "Ngô Tiến Dũng", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Hot press", "note": ""}, {"id": "Prod 2_360_W05606", "stt": 360, "code": "W05606", "name": "Ngô Vĩnh Long", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Hot press", "note": ""}, {"id": "Prod 2_361_W05608", "stt": 361, "code": "W05608", "name": "Nguyễn Quang Công", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Trimming", "note": ""}, {"id": "Prod 2_362_W05647", "stt": 362, "code": "W05647", "name": "Vương Đình Hùng", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Hot press", "note": ""}, {"id": "Prod 2_363_W05656", "stt": 363, "code": "W05656", "name": "Nguyễn Văn Thành", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Hot press", "note": ""}, {"id": "Prod 2_364_W05657", "stt": 364, "code": "W05657", "name": "Phạm Văn Huy", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Sawing + Shearing", "note": ""}, {"id": "Prod 2_365_W05664", "stt": 365, "code": "W05664", "name": "Nguyễn Văn Hiệp", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Hot press", "note": ""}, {"id": "Prod 2_366_W05670", "stt": 366, "code": "W05670", "name": "Lê Duy Hưng", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Hot press", "note": ""}, {"id": "Prod 2_367_W05697", "stt": 367, "code": "W05697", "name": "Trần Văn Nam", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Axle Press", "note": ""}, {"id": "Prod 2_368_W05716", "stt": 368, "code": "W05716", "name": "An Văn Chính", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Axle Press", "note": ""}, {"id": "Prod 2_369_W05723", "stt": 369, "code": "W05723", "name": "Đồng Văn Tập", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Axle Press", "note": ""}, {"id": "Prod 2_370_W05796", "stt": 370, "code": "W05796", "name": "Nguyễn Bá Truyền", "dept": "Prod 2", "department": "Production 2", "shop": "Forging", "group": "Cold Press", "note": ""}, {"id": "Prod 2_371_W00106", "stt": 371, "code": "W00106", "name": "Đỗ Anh Tuấn", "dept": "Prod 2", "department": "Production 2", "shop": "Heat treatment", "group": "", "note": ""}, {"id": "Prod 2_372_W00315", "stt": 372, "code": "W00315", "name": "Nguyễn Duy San", "dept": "Prod 2", "department": "Production 2", "shop": "Heat treatment", "group": "", "note": ""}, {"id": "Prod 2_373_W00487", "stt": 373, "code": "W00487", "name": "Đặng Văn Công", "dept": "Prod 2", "department": "Production 2", "shop": "Heat treatment", "group": "", "note": ""}, {"id": "Prod 2_374_W00618", "stt": 374, "code": "W00618", "name": "Chu Đình Long", "dept": "Prod 2", "department": "Production 2", "shop": "Heat treatment", "group": "", "note": ""}, {"id": "Prod 2_375_W00701", "stt": 375, "code": "W00701", "name": "Dương Văn Nam", "dept": "Prod 2", "department": "Production 2", "shop": "Heat treatment", "group": "", "note": ""}, {"id": "Prod 2_376_W00709", "stt": 376, "code": "W00709", "name": "Hầu Văn Quan", "dept": "Prod 2", "department": "Production 2", "shop": "Heat treatment", "group": "", "note": ""}, {"id": "Prod 2_377_W00751", "stt": 377, "code": "W00751", "name": "Hoàng Hữu Hùng", "dept": "Prod 2", "department": "Production 2", "shop": "Heat treatment", "group": "", "note": ""}, {"id": "Prod 2_378_W00754", "stt": 378, "code": "W00754", "name": "Nguyễn Văn Thắng", "dept": "Prod 2", "department": "Production 2", "shop": "Heat treatment", "group": "", "note": ""}, {"id": "Prod 2_379_W00793", "stt": 379, "code": "W00793", "name": "Mai Ngọc Lâm", "dept": "Prod 2", "department": "Production 2", "shop": "Heat treatment", "group": "", "note": ""}, {"id": "Prod 2_380_W00877", "stt": 380, "code": "W00877", "name": "Nguyễn Văn Hợp", "dept": "Prod 2", "department": "Production 2", "shop": "Heat treatment", "group": "", "note": ""}, {"id": "Prod 2_381_W01724", "stt": 381, "code": "W01724", "name": "Trần Anh Quang", "dept": "Prod 2", "department": "Production 2", "shop": "Heat treatment", "group": "", "note": ""}, {"id": "Prod 2_382_W01735", "stt": 382, "code": "W01735", "name": "Hoàng Văn Chính", "dept": "Prod 2", "department": "Production 2", "shop": "Heat treatment", "group": "", "note": ""}, {"id": "Prod 2_383_W01873", "stt": 383, "code": "W01873", "name": "Lương Thị Hiền", "dept": "Prod 2", "department": "Production 2", "shop": "Heat treatment", "group": "", "note": ""}, {"id": "Prod 2_384_W02222", "stt": 384, "code": "W02222", "name": "Nguyễn Văn Hùng", "dept": "Prod 2", "department": "Production 2", "shop": "Heat treatment", "group": "", "note": ""}, {"id": "Prod 2_385_W02235", "stt": 385, "code": "W02235", "name": "Phan Văn Thành", "dept": "Prod 2", "department": "Production 2", "shop": "Heat treatment", "group": "", "note": ""}, {"id": "Prod 2_386_W02361", "stt": 386, "code": "W02361", "name": "Trần Thị Giang", "dept": "Prod 2", "department": "Production 2", "shop": "Heat treatment", "group": "", "note": ""}, {"id": "Prod 2_387_W02409", "stt": 387, "code": "W02409", "name": "Nguyễn Thị Hằng", "dept": "Prod 2", "department": "Production 2", "shop": "Heat treatment", "group": "", "note": ""}, {"id": "Prod 2_388_W02419", "stt": 388, "code": "W02419", "name": "Nguyễn Thị Thu Hà", "dept": "Prod 2", "department": "Production 2", "shop": "Heat treatment", "group": "", "note": ""}, {"id": "Prod 2_389_W03019", "stt": 389, "code": "W03019", "name": "Kiều Thị Quý", "dept": "Prod 2", "department": "Production 2", "shop": "Heat treatment", "group": "", "note": ""}, {"id": "Prod 2_390_W03594", "stt": 390, "code": "W03594", "name": "Nguyễn Tiến Mạnh", "dept": "Prod 2", "department": "Production 2", "shop": "Heat treatment", "group": "", "note": ""}, {"id": "Prod 2_391_W03666", "stt": 391, "code": "W03666", "name": "Trần Văn Khánh", "dept": "Prod 2", "department": "Production 2", "shop": "Heat treatment", "group": "", "note": ""}, {"id": "Prod 2_392_W03800", "stt": 392, "code": "W03800", "name": "Nguyễn Thị Vân", "dept": "Prod 2", "department": "Production 2", "shop": "Heat treatment", "group": "", "note": ""}, {"id": "Prod 2_393_W04068", "stt": 393, "code": "W04068", "name": "Hoàng Đức Thắng", "dept": "Prod 2", "department": "Production 2", "shop": "Heat treatment", "group": "", "note": ""}, {"id": "Prod 2_394_W05146", "stt": 394, "code": "W05146", "name": "Lê Hồng Sơn", "dept": "Prod 2", "department": "Production 2", "shop": "Heat treatment", "group": "", "note": ""}, {"id": "Prod 2_395_W05385", "stt": 395, "code": "W05385", "name": "Nguyễn Thế Nam", "dept": "Prod 2", "department": "Production 2", "shop": "Heat treatment", "group": "", "note": ""}, {"id": "Prod 2_396_W05400", "stt": 396, "code": "W05400", "name": "Nguyễn Văn Vân", "dept": "Prod 2", "department": "Production 2", "shop": "Heat treatment", "group": "", "note": ""}, {"id": "Prod 2_397_W05545", "stt": 397, "code": "W05545", "name": "Nguyễn Thị Phương Thúy", "dept": "Prod 2", "department": "Production 2", "shop": "Heat treatment", "group": "", "note": ""}, {"id": "Prod 2_398_W05639", "stt": 398, "code": "W05639", "name": "Đỗ Văn Thắng", "dept": "Prod 2", "department": "Production 2", "shop": "Heat treatment", "group": "", "note": ""}, {"id": "Prod 2_399_W05655", "stt": 399, "code": "W05655", "name": "Nguyễn Văn Ngọt", "dept": "Prod 2", "department": "Production 2", "shop": "Heat treatment", "group": "", "note": ""}, {"id": "Prod 2_400_W05777", "stt": 400, "code": "W05777", "name": "Dương Văn Dũng", "dept": "Prod 2", "department": "Production 2", "shop": "Heat treatment", "group": "", "note": ""}, {"id": "Prod 2_401_W05879", "stt": 401, "code": "W05879", "name": "Đinh Thị Lý", "dept": "Prod 2", "department": "Production 2", "shop": "Heat treatment", "group": "", "note": ""}, {"id": "Prod 2_402_S00009", "stt": 402, "code": "S00009", "name": "Phạm Văn Trường", "dept": "Prod 2", "department": "Production 2", "shop": "Officer", "group": "", "note": ""}, {"id": "Prod 2_403_S00035", "stt": 403, "code": "S00035", "name": "Lê Tuấn Anh", "dept": "Prod 2", "department": "Production 2", "shop": "Officer", "group": "", "note": ""}, {"id": "Prod 2_404_S00038", "stt": 404, "code": "S00038", "name": "Nguyễn Anh Chuyền", "dept": "Prod 2", "department": "Production 2", "shop": "Officer", "group": "", "note": ""}, {"id": "Prod 2_405_S00044", "stt": 405, "code": "S00044", "name": "Nguyễn Thị Thương Huyền", "dept": "Prod 2", "department": "Production 2", "shop": "Officer", "group": "", "note": ""}, {"id": "Prod 2_406_S00071", "stt": 406, "code": "S00071", "name": "Phí Văn Mạnh", "dept": "Prod 2", "department": "Production 2", "shop": "Officer", "group": "", "note": ""}, {"id": "Prod 2_407_S00076", "stt": 407, "code": "S00076", "name": "Nguyễn Trọng An", "dept": "Prod 2", "department": "Production 2", "shop": "Officer", "group": "", "note": ""}, {"id": "Prod 2_408_S00113", "stt": 408, "code": "S00113", "name": "Phạm Đức Việt", "dept": "Prod 2", "department": "Production 2", "shop": "Officer", "group": "", "note": ""}, {"id": "Prod 2_409_S00119", "stt": 409, "code": "S00119", "name": "Lê Xuân Hoàng", "dept": "Prod 2", "department": "Production 2", "shop": "Officer", "group": "", "note": ""}, {"id": "Prod 2_410_S00147", "stt": 410, "code": "S00147", "name": "Nguyễn Thị Mai", "dept": "Prod 2", "department": "Production 2", "shop": "Officer", "group": "", "note": ""}, {"id": "Prod 2_411_W01042", "stt": 411, "code": "W01042", "name": "Nguyễn Thị Huyền My", "dept": "Prod 2", "department": "Production 2", "shop": "Officer", "group": "", "note": ""}, {"id": "Prod 2_412_W01827", "stt": 412, "code": "W01827", "name": "Đỗ Thị Mai Phương", "dept": "Prod 2", "department": "Production 2", "shop": "Officer", "group": "", "note": ""}, {"id": "Prod 2_413_W00324", "stt": 413, "code": "W00324", "name": "Nguyễn Thanh Tuấn", "dept": "Prod 2", "department": "Production 2", "shop": "Palfos", "group": "", "note": ""}, {"id": "Prod 2_414_W00410", "stt": 414, "code": "W00410", "name": "Trần Công Thế", "dept": "Prod 2", "department": "Production 2", "shop": "Palfos", "group": "", "note": ""}, {"id": "Prod 2_415_W00425", "stt": 415, "code": "W00425", "name": "Đinh Văn Phúc", "dept": "Prod 2", "department": "Production 2", "shop": "Palfos", "group": "", "note": ""}, {"id": "Prod 2_416_W00961", "stt": 416, "code": "W00961", "name": "Nguyễn Văn Ninh", "dept": "Prod 2", "department": "Production 2", "shop": "Palfos", "group": "", "note": ""}, {"id": "Prod 2_417_W00973", "stt": 417, "code": "W00973", "name": "Lương Thế Sức", "dept": "Prod 2", "department": "Production 2", "shop": "Palfos", "group": "", "note": ""}, {"id": "Prod 2_418_W01744", "stt": 418, "code": "W01744", "name": "Tạ Quốc Hoàng", "dept": "Prod 2", "department": "Production 2", "shop": "Palfos", "group": "", "note": ""}, {"id": "Prod 2_419_W04053", "stt": 419, "code": "W04053", "name": "Nguyễn Doãn Tùng", "dept": "Prod 2", "department": "Production 2", "shop": "Palfos", "group": "", "note": ""}, {"id": "Prod 2_420_W04828", "stt": 420, "code": "W04828", "name": "Hà Vũ Hà", "dept": "Prod 2", "department": "Production 2", "shop": "Palfos", "group": "", "note": ""}, {"id": "Prod 2_421_W05586", "stt": 421, "code": "W05586", "name": "Đỗ Văn Mạnh", "dept": "Prod 2", "department": "Production 2", "shop": "Palfos", "group": "", "note": ""}, {"id": "Prod 2_422_W05642", "stt": 422, "code": "W05642", "name": "Ngô Quang Toản", "dept": "Prod 2", "department": "Production 2", "shop": "Palfos", "group": "", "note": ""}, {"id": "Prod 2_423_W00338", "stt": 423, "code": "W00338", "name": "Bùi Thị Thuý Tình", "dept": "Prod 2", "department": "Production 2", "shop": "Production Control", "group": "", "note": ""}, {"id": "Prod 2_424_W00478", "stt": 424, "code": "W00478", "name": "Nguyễn Thị Thanh Vân", "dept": "Prod 2", "department": "Production 2", "shop": "Production Control", "group": "", "note": ""}, {"id": "Prod 2_425_W00564", "stt": 425, "code": "W00564", "name": "Nguyễn Phan Hiền", "dept": "Prod 2", "department": "Production 2", "shop": "Production Control", "group": "", "note": ""}, {"id": "Prod 2_426_W00962", "stt": 426, "code": "W00962", "name": "Mai Thị Oanh", "dept": "Prod 2", "department": "Production 2", "shop": "Production Control", "group": "", "note": ""}, {"id": "Prod 2_427_W01364", "stt": 427, "code": "W01364", "name": "Nguyễn Thị Tường", "dept": "Prod 2", "department": "Production 2", "shop": "Production Control", "group": "", "note": ""}, {"id": "Prod 2_428_W02009", "stt": 428, "code": "W02009", "name": "Nguyễn Thị Oanh", "dept": "Prod 2", "department": "Production 2", "shop": "Production Control", "group": "", "note": ""}, {"id": "Prod 2_429_W05296", "stt": 429, "code": "W05296", "name": "Dương Thị Huyền", "dept": "Prod 2", "department": "Production 2", "shop": "Production Control", "group": "", "note": ""}, {"id": "Prod 2_430_W05633", "stt": 430, "code": "W05633", "name": "Nguyễn Thị Minh Dung", "dept": "Prod 2", "department": "Production 2", "shop": "Production Control", "group": "", "note": ""}, {"id": "Prod 2_431_W00310", "stt": 431, "code": "W00310", "name": "Nguyễn Thị Huế", "dept": "Prod 2", "department": "Production 2", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 2_432_W00329", "stt": 432, "code": "W00329", "name": "Nguyễn Văn Hiển", "dept": "Prod 2", "department": "Production 2", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 2_433_W00336", "stt": 433, "code": "W00336", "name": "Nguyễn Thị Thuý Mai", "dept": "Prod 2", "department": "Production 2", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 2_434_W00342", "stt": 434, "code": "W00342", "name": "Hoàng Thị Huế", "dept": "Prod 2", "department": "Production 2", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 2_435_W00353", "stt": 435, "code": "W00353", "name": "Nguyễn Thị Hiền", "dept": "Prod 2", "department": "Production 2", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 2_436_W00362", "stt": 436, "code": "W00362", "name": "Đoàn Văn Cường", "dept": "Prod 2", "department": "Production 2", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 2_437_W00374", "stt": 437, "code": "W00374", "name": "Hoàng Thiện Đường", "dept": "Prod 2", "department": "Production 2", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 2_438_W00420", "stt": 438, "code": "W00420", "name": "Bùi Thị Nhường", "dept": "Prod 2", "department": "Production 2", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 2_439_W00422", "stt": 439, "code": "W00422", "name": "Nguyễn Thị Phương", "dept": "Prod 2", "department": "Production 2", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 2_440_W00455", "stt": 440, "code": "W00455", "name": "Bùi Quang Đoàn", "dept": "Prod 2", "department": "Production 2", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 2_441_W00461", "stt": 441, "code": "W00461", "name": "Hoàng Thị út", "dept": "Prod 2", "department": "Production 2", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 2_442_W00578", "stt": 442, "code": "W00578", "name": "Nguyễn Doãn Hải", "dept": "Prod 2", "department": "Production 2", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 2_443_W00736", "stt": 443, "code": "W00736", "name": "Trần Văn Trang", "dept": "Prod 2", "department": "Production 2", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 2_444_W00762", "stt": 444, "code": "W00762", "name": "Lại Hữu Mừng", "dept": "Prod 2", "department": "Production 2", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 2_445_W00923", "stt": 445, "code": "W00923", "name": "Đỗ Thị Dung", "dept": "Prod 2", "department": "Production 2", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 2_446_W00965", "stt": 446, "code": "W00965", "name": "Dương Thị Phương", "dept": "Prod 2", "department": "Production 2", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 2_447_W00992", "stt": 447, "code": "W00992", "name": "Ngô Thị ánh Tuyết", "dept": "Prod 2", "department": "Production 2", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 2_448_W01094", "stt": 448, "code": "W01094", "name": "Dương Thị Thanh Xuân", "dept": "Prod 2", "department": "Production 2", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 2_449_W01224", "stt": 449, "code": "W01224", "name": "Lê Văn Tuấn", "dept": "Prod 2", "department": "Production 2", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 2_450_W01242", "stt": 450, "code": "W01242", "name": "Phạm Văn Đại", "dept": "Prod 2", "department": "Production 2", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 2_451_W01274", "stt": 451, "code": "W01274", "name": "Phạm Thị Hải", "dept": "Prod 2", "department": "Production 2", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 2_452_W01314", "stt": 452, "code": "W01314", "name": "Vũ Thị Bắc", "dept": "Prod 2", "department": "Production 2", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 2_453_W01379", "stt": 453, "code": "W01379", "name": "Nguyễn Duy Biên", "dept": "Prod 2", "department": "Production 2", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 2_454_W01482", "stt": 454, "code": "W01482", "name": "Vũ Thị Hải", "dept": "Prod 2", "department": "Production 2", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 2_455_W01510", "stt": 455, "code": "W01510", "name": "Nguyễn Văn Thái", "dept": "Prod 2", "department": "Production 2", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 2_456_W01542", "stt": 456, "code": "W01542", "name": "Nguyễn Văn Tiến", "dept": "Prod 2", "department": "Production 2", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 2_457_W01723", "stt": 457, "code": "W01723", "name": "Trương Văn Tuyên", "dept": "Prod 2", "department": "Production 2", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 2_458_W01734", "stt": 458, "code": "W01734", "name": "Vũ Văn Chinh", "dept": "Prod 2", "department": "Production 2", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 2_459_W01759", "stt": 459, "code": "W01759", "name": "Hoàng Văn Quỳnh", "dept": "Prod 2", "department": "Production 2", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 2_460_W01767", "stt": 460, "code": "W01767", "name": "Nguyễn Duy Thắng", "dept": "Prod 2", "department": "Production 2", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 2_461_W01825", "stt": 461, "code": "W01825", "name": "La Thị Minh", "dept": "Prod 2", "department": "Production 2", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 2_462_W01838", "stt": 462, "code": "W01838", "name": "Trần Thị Hòa", "dept": "Prod 2", "department": "Production 2", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 2_463_W01856", "stt": 463, "code": "W01856", "name": "Nguyễn Thị Thanh Thuận", "dept": "Prod 2", "department": "Production 2", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 2_464_W01866", "stt": 464, "code": "W01866", "name": "Lê Thị Chi", "dept": "Prod 2", "department": "Production 2", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 2_465_W01867", "stt": 465, "code": "W01867", "name": "Cao Thị Bích Lương", "dept": "Prod 2", "department": "Production 2", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 2_466_W01889", "stt": 466, "code": "W01889", "name": "Nguyễn Hoàng Quân", "dept": "Prod 2", "department": "Production 2", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 2_467_W01948", "stt": 467, "code": "W01948", "name": "Nguyễn Hữu Long", "dept": "Prod 2", "department": "Production 2", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 2_468_W02105", "stt": 468, "code": "W02105", "name": "Nguyễn Đức Nam", "dept": "Prod 2", "department": "Production 2", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 2_469_W02410", "stt": 469, "code": "W02410", "name": "Lê Thị Nhung", "dept": "Prod 2", "department": "Production 2", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 2_470_W02548", "stt": 470, "code": "W02548", "name": "Nguyễn Thị Ngọc", "dept": "Prod 2", "department": "Production 2", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 2_471_W02768", "stt": 471, "code": "W02768", "name": "Nguyễn Duy Khải", "dept": "Prod 2", "department": "Production 2", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 2_472_W03316", "stt": 472, "code": "W03316", "name": "Trần Thị Duyên", "dept": "Prod 2", "department": "Production 2", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 2_473_W03488", "stt": 473, "code": "W03488", "name": "Phạm Thị Nhung", "dept": "Prod 2", "department": "Production 2", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 2_474_W03513", "stt": 474, "code": "W03513", "name": "Phạm Thị Thúy", "dept": "Prod 2", "department": "Production 2", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 2_475_W03582", "stt": 475, "code": "W03582", "name": "Quách Thị Thức", "dept": "Prod 2", "department": "Production 2", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 2_476_W04010", "stt": 476, "code": "W04010", "name": "Phạm Hồng Thúy", "dept": "Prod 2", "department": "Production 2", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 2_477_W04102", "stt": 477, "code": "W04102", "name": "Nguyễn Thị Vân", "dept": "Prod 2", "department": "Production 2", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 2_478_W04108", "stt": 478, "code": "W04108", "name": "Nguyễn Thị Hảo", "dept": "Prod 2", "department": "Production 2", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 2_479_W04421", "stt": 479, "code": "W04421", "name": "Lê Thị Bình", "dept": "Prod 2", "department": "Production 2", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 2_480_W04714", "stt": 480, "code": "W04714", "name": "Khổng Thị Hảo", "dept": "Prod 2", "department": "Production 2", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 2_481_W04721", "stt": 481, "code": "W04721", "name": "Nguyễn Thị Lý", "dept": "Prod 2", "department": "Production 2", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 2_482_W04891", "stt": 482, "code": "W04891", "name": "Nguyễn Thế Đại", "dept": "Prod 2", "department": "Production 2", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 2_483_W05126", "stt": 483, "code": "W05126", "name": "Bùi Thị Thu Liên", "dept": "Prod 2", "department": "Production 2", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 2_484_W05301", "stt": 484, "code": "W05301", "name": "Nguyễn Ngọc Long", "dept": "Prod 2", "department": "Production 2", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 2_485_W05315", "stt": 485, "code": "W05315", "name": "Nguyễn Thị Thanh", "dept": "Prod 2", "department": "Production 2", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 2_486_W05485", "stt": 486, "code": "W05485", "name": "Lê Thị Kim Liên", "dept": "Prod 2", "department": "Production 2", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 2_487_W05616", "stt": 487, "code": "W05616", "name": "Nguyễn Thị Tất Vinh", "dept": "Prod 2", "department": "Production 2", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 2_488_W05774", "stt": 488, "code": "W05774", "name": "Nguyễn Thị Hoan", "dept": "Prod 2", "department": "Production 2", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 2_489_W05820", "stt": 489, "code": "W05820", "name": "Hoàng Như Thuỳ", "dept": "Prod 2", "department": "Production 2", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 2_490_W00029", "stt": 490, "code": "W00029", "name": "Nguyễn Văn Trình", "dept": "Prod 2", "department": "Production 2", "shop": "Regrinding", "group": "", "note": ""}, {"id": "Prod 2_491_W00502", "stt": 491, "code": "W00502", "name": "Lê Văn Thuỷ", "dept": "Prod 2", "department": "Production 2", "shop": "Regrinding", "group": "", "note": ""}, {"id": "Prod 2_492_W00865", "stt": 492, "code": "W00865", "name": "Nguyễn Văn Điệp", "dept": "Prod 2", "department": "Production 2", "shop": "Regrinding", "group": "", "note": ""}, {"id": "Prod 2_493_W00937", "stt": 493, "code": "W00937", "name": "Trần Anh Hoà", "dept": "Prod 2", "department": "Production 2", "shop": "Regrinding", "group": "", "note": ""}, {"id": "Prod 2_494_W01553", "stt": 494, "code": "W01553", "name": "Nguyễn Ngọc Giang", "dept": "Prod 2", "department": "Production 2", "shop": "Regrinding", "group": "", "note": ""}, {"id": "Prod 2_495_W02367", "stt": 495, "code": "W02367", "name": "Lê Quang Linh", "dept": "Prod 2", "department": "Production 2", "shop": "Regrinding", "group": "", "note": ""}, {"id": "Prod 2_496_W02446", "stt": 496, "code": "W02446", "name": "Đào Anh Tuấn", "dept": "Prod 2", "department": "Production 2", "shop": "Regrinding", "group": "", "note": ""}, {"id": "Prod 3_1_W00037", "stt": 1, "code": "W00037", "name": "Trần Kim Tú", "dept": "Prod 3", "department": "Production 3", "shop": "Die Casting", "group": "", "note": ""}, {"id": "Prod 3_2_W00082", "stt": 2, "code": "W00082", "name": "Nguyễn Văn Khang", "dept": "Prod 3", "department": "Production 3", "shop": "Die Casting", "group": "", "note": ""}, {"id": "Prod 3_3_W00216", "stt": 3, "code": "W00216", "name": "Nguyễn Văn Luyến", "dept": "Prod 3", "department": "Production 3", "shop": "Die Casting", "group": "", "note": ""}, {"id": "Prod 3_4_W00506", "stt": 4, "code": "W00506", "name": "Nguyễn Đức Chiến", "dept": "Prod 3", "department": "Production 3", "shop": "Die Casting", "group": "", "note": ""}, {"id": "Prod 3_5_W00539", "stt": 5, "code": "W00539", "name": "Trần Văn Duy", "dept": "Prod 3", "department": "Production 3", "shop": "Die Casting", "group": "", "note": ""}, {"id": "Prod 3_6_W00687", "stt": 6, "code": "W00687", "name": "Dương Đức Mạnh", "dept": "Prod 3", "department": "Production 3", "shop": "Die Casting", "group": "", "note": ""}, {"id": "Prod 3_7_W01051", "stt": 7, "code": "W01051", "name": "Nguyễn Khả Sơn", "dept": "Prod 3", "department": "Production 3", "shop": "Die Casting", "group": "", "note": ""}, {"id": "Prod 3_8_W01417", "stt": 8, "code": "W01417", "name": "Nguyễn Quảng Đại", "dept": "Prod 3", "department": "Production 3", "shop": "Die Casting", "group": "", "note": ""}, {"id": "Prod 3_9_W01583", "stt": 9, "code": "W01583", "name": "Nguyễn Văn Công", "dept": "Prod 3", "department": "Production 3", "shop": "Die Casting", "group": "", "note": ""}, {"id": "Prod 3_10_W01609", "stt": 10, "code": "W01609", "name": "Dương Ngọc Long", "dept": "Prod 3", "department": "Production 3", "shop": "Die Casting", "group": "", "note": ""}, {"id": "Prod 3_11_W01709", "stt": 11, "code": "W01709", "name": "Vũ Văn Hùng", "dept": "Prod 3", "department": "Production 3", "shop": "Die Casting", "group": "", "note": ""}, {"id": "Prod 3_12_W02119", "stt": 12, "code": "W02119", "name": "Nguyễn Đức Huỳnh", "dept": "Prod 3", "department": "Production 3", "shop": "Die Casting", "group": "", "note": ""}, {"id": "Prod 3_13_W02267", "stt": 13, "code": "W02267", "name": "Lý Mạnh Hà", "dept": "Prod 3", "department": "Production 3", "shop": "Die Casting", "group": "", "note": ""}, {"id": "Prod 3_14_W02612", "stt": 14, "code": "W02612", "name": "Trần Tiến Dũng", "dept": "Prod 3", "department": "Production 3", "shop": "Die Casting", "group": "", "note": ""}, {"id": "Prod 3_15_W02887", "stt": 15, "code": "W02887", "name": "Vũ Huy Điền", "dept": "Prod 3", "department": "Production 3", "shop": "Die Casting", "group": "", "note": ""}, {"id": "Prod 3_16_W03514", "stt": 16, "code": "W03514", "name": "Trần Văn Hải", "dept": "Prod 3", "department": "Production 3", "shop": "Die Casting", "group": "", "note": ""}, {"id": "Prod 3_17_W03900", "stt": 17, "code": "W03900", "name": "Nguyễn Đức Hạnh", "dept": "Prod 3", "department": "Production 3", "shop": "Die Casting", "group": "", "note": ""}, {"id": "Prod 3_18_W03907", "stt": 18, "code": "W03907", "name": "Nguyễn Văn Dương", "dept": "Prod 3", "department": "Production 3", "shop": "Die Casting", "group": "", "note": ""}, {"id": "Prod 3_19_W03923", "stt": 19, "code": "W03923", "name": "Nguyễn Văn Vùng", "dept": "Prod 3", "department": "Production 3", "shop": "Die Casting", "group": "", "note": ""}, {"id": "Prod 3_20_W04201", "stt": 20, "code": "W04201", "name": "Nguyễn Văn Ninh", "dept": "Prod 3", "department": "Production 3", "shop": "Die Casting", "group": "", "note": ""}, {"id": "Prod 3_21_W04300", "stt": 21, "code": "W04300", "name": "Nguyễn Văn Chung", "dept": "Prod 3", "department": "Production 3", "shop": "Die Casting", "group": "", "note": ""}, {"id": "Prod 3_22_W04682", "stt": 22, "code": "W04682", "name": "Nguyễn Văn Liên", "dept": "Prod 3", "department": "Production 3", "shop": "Die Casting", "group": "", "note": ""}, {"id": "Prod 3_23_W05030", "stt": 23, "code": "W05030", "name": "Vũ Bá Văn", "dept": "Prod 3", "department": "Production 3", "shop": "Die Casting", "group": "", "note": ""}, {"id": "Prod 3_24_W05040", "stt": 24, "code": "W05040", "name": "Nguyễn Đức Hào", "dept": "Prod 3", "department": "Production 3", "shop": "Die Casting", "group": "", "note": ""}, {"id": "Prod 3_25_W05048", "stt": 25, "code": "W05048", "name": "Vũ Thành Đô", "dept": "Prod 3", "department": "Production 3", "shop": "Die Casting", "group": "", "note": ""}, {"id": "Prod 3_26_W05050", "stt": 26, "code": "W05050", "name": "Nguyễn Hồng Quân", "dept": "Prod 3", "department": "Production 3", "shop": "Die Casting", "group": "", "note": ""}, {"id": "Prod 3_27_W05228", "stt": 27, "code": "W05228", "name": "Phạm Văn Thiệp", "dept": "Prod 3", "department": "Production 3", "shop": "Die Casting", "group": "", "note": ""}, {"id": "Prod 3_28_W05424", "stt": 28, "code": "W05424", "name": "Lê Văn Chữ", "dept": "Prod 3", "department": "Production 3", "shop": "Die Casting", "group": "", "note": ""}, {"id": "Prod 3_29_W05548", "stt": 29, "code": "W05548", "name": "Nguyễn Trung Đức", "dept": "Prod 3", "department": "Production 3", "shop": "Die Casting", "group": "", "note": ""}, {"id": "Prod 3_30_W05630", "stt": 30, "code": "W05630", "name": "Nguyễn Văn Quỳnh", "dept": "Prod 3", "department": "Production 3", "shop": "Die Casting", "group": "", "note": ""}, {"id": "Prod 3_31_W05671", "stt": 31, "code": "W05671", "name": "Ngô Anh Quyền", "dept": "Prod 3", "department": "Production 3", "shop": "Die Casting", "group": "", "note": ""}, {"id": "Prod 3_32_W05745", "stt": 32, "code": "W05745", "name": "Nguyễn Văn Quý", "dept": "Prod 3", "department": "Production 3", "shop": "Die Casting", "group": "", "note": ""}, {"id": "Prod 3_33_W05752", "stt": 33, "code": "W05752", "name": "Trần Thanh Hoài", "dept": "Prod 3", "department": "Production 3", "shop": "Die Casting", "group": "", "note": ""}, {"id": "Prod 3_34_W05787", "stt": 34, "code": "W05787", "name": "Đỗ Đăng Chiến", "dept": "Prod 3", "department": "Production 3", "shop": "Die Casting", "group": "", "note": ""}, {"id": "Prod 3_35_W05840", "stt": 35, "code": "W05840", "name": "Vương Trung Hiếu", "dept": "Prod 3", "department": "Production 3", "shop": "Die Casting", "group": "", "note": ""}, {"id": "Prod 3_36_W00210", "stt": 36, "code": "W00210", "name": "Nguyễn Quốc Đức", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_37_W00283", "stt": 37, "code": "W00283", "name": "Nguyễn Thị Thu Hương", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_38_W00393", "stt": 38, "code": "W00393", "name": "Nguyễn Thị Anh", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_39_W00480", "stt": 39, "code": "W00480", "name": "Phạm Thị Huyền", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_40_W01088", "stt": 40, "code": "W01088", "name": "Lê Thị Ngà", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_41_W01172", "stt": 41, "code": "W01172", "name": "Đỗ Thị Tâm", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_42_W01173", "stt": 42, "code": "W01173", "name": "Hoàng Thị Thu", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_43_W01174", "stt": 43, "code": "W01174", "name": "Nguyễn Đức Trọng", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_44_W01183", "stt": 44, "code": "W01183", "name": "Triệu Thị Sen", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_45_W01331", "stt": 45, "code": "W01331", "name": "Dương Thị Xuyến", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_46_W01357", "stt": 46, "code": "W01357", "name": "Lê Thị Thúy Nga", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_47_W01413", "stt": 47, "code": "W01413", "name": "Trần Thị Hồng Tính", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_48_W01424", "stt": 48, "code": "W01424", "name": "Chu Văn Bạn", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_49_W01444", "stt": 49, "code": "W01444", "name": "Trần Thị Hồng Mây", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_50_W01468", "stt": 50, "code": "W01468", "name": "Nguyễn Thị Mai", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_51_W01477", "stt": 51, "code": "W01477", "name": "Hoàng Thị Kiều Oanh", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_52_W01506", "stt": 52, "code": "W01506", "name": "Lê Văn Hiệu", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_53_W01518", "stt": 53, "code": "W01518", "name": "Lê Công Dương", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_54_W01521", "stt": 54, "code": "W01521", "name": "Dương Xuân Định", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_55_W01524", "stt": 55, "code": "W01524", "name": "Tô Như Quỳnh", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_56_W01546", "stt": 56, "code": "W01546", "name": "Bùi Thị Châu", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_57_W01567", "stt": 57, "code": "W01567", "name": "Nguyễn Thị Thúy Vân", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_58_W01814", "stt": 58, "code": "W01814", "name": "Nguyễn Thị Thúy", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_59_W02000", "stt": 59, "code": "W02000", "name": "Ngô Thị Hoa", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_60_W02050", "stt": 60, "code": "W02050", "name": "Lê Công Dũng", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_61_W02069", "stt": 61, "code": "W02069", "name": "Nguyễn Văn Quân", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_62_W02080", "stt": 62, "code": "W02080", "name": "Nguyễn Văn Tạo", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_63_W02388", "stt": 63, "code": "W02388", "name": "Hoàng Thị Phương", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_64_W02574", "stt": 64, "code": "W02574", "name": "Lê Thị Nguyệt", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_65_W02578", "stt": 65, "code": "W02578", "name": "Nguyễn Văn Tần", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_66_W02579", "stt": 66, "code": "W02579", "name": "La Văn Thật", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_67_W02585", "stt": 67, "code": "W02585", "name": "Nguyễn Văn Nam", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_68_W02601", "stt": 68, "code": "W02601", "name": "Hà Thị Lựu", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_69_W02680", "stt": 69, "code": "W02680", "name": "Lê Thị Phượng", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_70_W02683", "stt": 70, "code": "W02683", "name": "Trần Thị Hiền", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_71_W02815", "stt": 71, "code": "W02815", "name": "Trần Thị Làn", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_72_W02824", "stt": 72, "code": "W02824", "name": "Trần Văn Được", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_73_W02825", "stt": 73, "code": "W02825", "name": "Nguyễn Thị Thu Hoài", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_74_W02829", "stt": 74, "code": "W02829", "name": "Lưu Thị Thảo", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_75_W03152", "stt": 75, "code": "W03152", "name": "Nguyễn Thị Hà Thu", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_76_W03376", "stt": 76, "code": "W03376", "name": "Đoàn Văn Tuyên", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_77_W03395", "stt": 77, "code": "W03395", "name": "Nguyễn Minh Đức", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_78_W03396", "stt": 78, "code": "W03396", "name": "Trần Đức Hanh", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_79_W03748", "stt": 79, "code": "W03748", "name": "Phạm Đình Ngọc", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_80_W03791", "stt": 80, "code": "W03791", "name": "Trịnh Hà Cường", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_81_W03914", "stt": 81, "code": "W03914", "name": "Dương Thị Ly", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_82_W03920", "stt": 82, "code": "W03920", "name": "Hà Thị Thu", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_83_W04164", "stt": 83, "code": "W04164", "name": "Hoàng Đức Vượng", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_84_W04497", "stt": 84, "code": "W04497", "name": "Nguyễn Văn Lễ", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_85_W04505", "stt": 85, "code": "W04505", "name": "Nguyễn Tài Thu", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_86_W04667", "stt": 86, "code": "W04667", "name": "Trần Quang Huy", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_87_W04957", "stt": 87, "code": "W04957", "name": "Đỗ Quang Bằng", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_88_W04974", "stt": 88, "code": "W04974", "name": "Nguyễn Văn Hồi", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_89_W04986", "stt": 89, "code": "W04986", "name": "Lưu Văn Liệp", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_90_W04994", "stt": 90, "code": "W04994", "name": "Nguyễn Xuân Luyện", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_91_W05035", "stt": 91, "code": "W05035", "name": "Nguyễn Thị Yến", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_92_W05142", "stt": 92, "code": "W05142", "name": "Nguyễn Văn Quân", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_93_W05184", "stt": 93, "code": "W05184", "name": "Nguyễn Mạnh Cường", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_94_W05188", "stt": 94, "code": "W05188", "name": "Đỗ Đăng Đông", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_95_W05203", "stt": 95, "code": "W05203", "name": "Trần Doãn Khánh", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_96_W05232", "stt": 96, "code": "W05232", "name": "Trần Hồng Thúy", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_97_W05344", "stt": 97, "code": "W05344", "name": "Bùi Quang Tuyên", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_98_W05354", "stt": 98, "code": "W05354", "name": "Nguyễn Văn Ngọc", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_99_W05409", "stt": 99, "code": "W05409", "name": "Nguyễn Văn Dũng", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_100_W05429", "stt": 100, "code": "W05429", "name": "Phạm Tiến Đức", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_101_W05441", "stt": 101, "code": "W05441", "name": "Nguyễn Đức Hùng", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_102_W05468", "stt": 102, "code": "W05468", "name": "Nguyễn Thanh Tịnh", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_103_W05479", "stt": 103, "code": "W05479", "name": "Hoàng Văn Sỹ", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_104_W05681", "stt": 104, "code": "W05681", "name": "Nguyễn Xuân Mậu", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_105_W05686", "stt": 105, "code": "W05686", "name": "Phạm Văn Chung", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_106_W05688", "stt": 106, "code": "W05688", "name": "Tạ Văn Minh", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_107_W05692", "stt": 107, "code": "W05692", "name": "Trần Thị Nguyệt", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_108_W05696", "stt": 108, "code": "W05696", "name": "Trần Văn Khánh", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_109_W05699", "stt": 109, "code": "W05699", "name": "Trần Văn Vui", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_110_W05702", "stt": 110, "code": "W05702", "name": "Trương Công Minh", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_111_W05703", "stt": 111, "code": "W05703", "name": "Trương Công Nam", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_112_W05706", "stt": 112, "code": "W05706", "name": "Đặng Thị Chất", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_113_W05711", "stt": 113, "code": "W05711", "name": "Nguyễn Thị Phương", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_114_W05712", "stt": 114, "code": "W05712", "name": "Nguyễn Thị Thúy", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_115_W05714", "stt": 115, "code": "W05714", "name": "Trịnh Thị Hạnh", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_116_W05715", "stt": 116, "code": "W05715", "name": "Trịnh Thị Mơ", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_117_W05722", "stt": 117, "code": "W05722", "name": "Đồng Văn Nam", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_118_W05725", "stt": 118, "code": "W05725", "name": "Dương Văn Thảo", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_119_W05730", "stt": 119, "code": "W05730", "name": "Nguyễn Đình Huấn", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_120_W05734", "stt": 120, "code": "W05734", "name": "Nguyễn Tiến Lực", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_121_W05750", "stt": 121, "code": "W05750", "name": "Tạ Văn Công", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_122_W05751", "stt": 122, "code": "W05751", "name": "Tạ Văn Đông", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_123_W05757", "stt": 123, "code": "W05757", "name": "Nguyễn Thị Hiền", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_124_W05767", "stt": 124, "code": "W05767", "name": "Nguyễn Văn Vinh", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_125_W05772", "stt": 125, "code": "W05772", "name": "Lê Văn Tuấn", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_126_W05828", "stt": 126, "code": "W05828", "name": "Nguyễn Tuấn Đạt", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_127_W05832", "stt": 127, "code": "W05832", "name": "Đồng Thị Phương", "dept": "Prod 3", "department": "Production 3", "shop": "Finishing", "group": "", "note": ""}, {"id": "Prod 3_128_W00156", "stt": 128, "code": "W00156", "name": "Nguyễn Thị Tâm", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_129_W00206", "stt": 129, "code": "W00206", "name": "Nguyễn Huy Khanh", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_130_W00221", "stt": 130, "code": "W00221", "name": "Phạm Viết Thông", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_131_W00250", "stt": 131, "code": "W00250", "name": "Nguyễn Văn Đại", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_132_W00508", "stt": 132, "code": "W00508", "name": "Nguyễn Đức Thành", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_133_W00621", "stt": 133, "code": "W00621", "name": "Nguyễn Tiến Công", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_134_W01025", "stt": 134, "code": "W01025", "name": "Lê Văn Hùng", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_135_W01079", "stt": 135, "code": "W01079", "name": "Nguyễn Anh Tuấn", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_136_W01356", "stt": 136, "code": "W01356", "name": "Phan Thị Tuyết Mai", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_137_W01363", "stt": 137, "code": "W01363", "name": "Nguyễn Tràng Quỳnh", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_138_W01374", "stt": 138, "code": "W01374", "name": "Thái Thị Vui", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_139_W01480", "stt": 139, "code": "W01480", "name": "Lương Thị Bích", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_140_W01594", "stt": 140, "code": "W01594", "name": "Chu Thị Kim Phúc", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_141_W01608", "stt": 141, "code": "W01608", "name": "Nguyễn Thị Tình", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_142_W01710", "stt": 142, "code": "W01710", "name": "Nguyễn Văn Thanh", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_143_W01732", "stt": 143, "code": "W01732", "name": "Trịnh Văn Công", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_144_W02049", "stt": 144, "code": "W02049", "name": "Nguyễn Văn Anh", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_145_W02116", "stt": 145, "code": "W02116", "name": "Nguyễn Văn Kính", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_146_W02164", "stt": 146, "code": "W02164", "name": "Nguyễn Thị Liên", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_147_W02169", "stt": 147, "code": "W02169", "name": "Đinh Thị Hoa", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_148_W02214", "stt": 148, "code": "W02214", "name": "Trần Văn Phương", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_149_W02229", "stt": 149, "code": "W02229", "name": "Ngọ văn Cường", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_150_W02272", "stt": 150, "code": "W02272", "name": "Trần Hữu Mạnh", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_151_W02597", "stt": 151, "code": "W02597", "name": "Nghiêm Minh Thái", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_152_W02628", "stt": 152, "code": "W02628", "name": "Đỗ Thị Hiền", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_153_W02665", "stt": 153, "code": "W02665", "name": "Nguyễn Thị Trang", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_154_W02707", "stt": 154, "code": "W02707", "name": "Đỗ Ngọc Tuyên", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_155_W02858", "stt": 155, "code": "W02858", "name": "Phạm Văn Tuấn", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_156_W03014", "stt": 156, "code": "W03014", "name": "Phan Văn Tuấn", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_157_W04110", "stt": 157, "code": "W04110", "name": "Dương Thị Thanh", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_158_W04186", "stt": 158, "code": "W04186", "name": "Trịnh Văn Tuyên", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_159_W04203", "stt": 159, "code": "W04203", "name": "Ngô Văn Quyền", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_160_W04329", "stt": 160, "code": "W04329", "name": "Nguyễn Doãn Thắng", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_161_W04378", "stt": 161, "code": "W04378", "name": "Nguyễn Doãn Điệp", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_162_W04476", "stt": 162, "code": "W04476", "name": "Doãn Thị Thịnh", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_163_W04544", "stt": 163, "code": "W04544", "name": "Nguyễn Thị Phương", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_164_W04591", "stt": 164, "code": "W04591", "name": "Hoàng Thị Trang", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_165_W04651", "stt": 165, "code": "W04651", "name": "Đỗ Thị Miên", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_166_W04959", "stt": 166, "code": "W04959", "name": "Phạm Văn Bộ", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_167_W04975", "stt": 167, "code": "W04975", "name": "Phạm Thị Thu Huế", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_168_W05084", "stt": 168, "code": "W05084", "name": "Vương Xuân Ngọc", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_169_W05220", "stt": 169, "code": "W05220", "name": "Nguyễn Thanh Nhàn", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_170_W05279", "stt": 170, "code": "W05279", "name": "Nguyễn Văn Đạt", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_171_W05312", "stt": 171, "code": "W05312", "name": "Đỗ Hồng Quân", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_172_W05331", "stt": 172, "code": "W05331", "name": "Hoàng Minh Thái", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_173_W05447", "stt": 173, "code": "W05447", "name": "Nguyễn Văn Linh", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_174_W05462", "stt": 174, "code": "W05462", "name": "Nguyễn Phi Thăng", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_175_W05512", "stt": 175, "code": "W05512", "name": "Nguyễn Thành Long", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_176_W05687", "stt": 176, "code": "W05687", "name": "Tạ Duy Đại", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_177_W05690", "stt": 177, "code": "W05690", "name": "Trần Minh Đạt", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_178_W05694", "stt": 178, "code": "W05694", "name": "Trần Văn Chung", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_179_W05700", "stt": 179, "code": "W05700", "name": "Triệu Văn Trinh", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_180_W05701", "stt": 180, "code": "W05701", "name": "Trịnh Thị Thùy Trang", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_181_W05704", "stt": 181, "code": "W05704", "name": "Vương Xuân Thanh", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_182_W05713", "stt": 182, "code": "W05713", "name": "Phạm Thị Thu Hà", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_183_W05717", "stt": 183, "code": "W05717", "name": "Đào Minh Thảo", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_184_W05724", "stt": 184, "code": "W05724", "name": "Dương Ngọc Dầu", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_185_W05729", "stt": 185, "code": "W05729", "name": "Mai Văn Thành", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_186_W05735", "stt": 186, "code": "W05735", "name": "Nguyễn Tùng Lâm", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_187_W05747", "stt": 187, "code": "W05747", "name": "Nguyễn Văn Tiến", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_188_W05758", "stt": 188, "code": "W05758", "name": "Nguyễn Thị Huyền", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_189_W05763", "stt": 189, "code": "W05763", "name": "Nguyễn Kim Thanh", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_190_W05769", "stt": 190, "code": "W05769", "name": "Đỗ Văn Trình", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_191_W05780", "stt": 191, "code": "W05780", "name": "Nguyễn Thị Hưng", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_192_W05834", "stt": 192, "code": "W05834", "name": "Lê Mạnh Chiến", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_193_W05841", "stt": 193, "code": "W05841", "name": "Đỗ Quang Hải", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_194_W05842", "stt": 194, "code": "W05842", "name": "Bùi Tiến Bút", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_195_W05843", "stt": 195, "code": "W05843", "name": "Nguyễn Thành Trung", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_196_W05846", "stt": 196, "code": "W05846", "name": "Nguyễn Thị Tố Như", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_197_W05848", "stt": 197, "code": "W05848", "name": "Phan Duy Vinh", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_198_W05883", "stt": 198, "code": "W05883", "name": "Trần Thị Dung", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_199_W05885", "stt": 199, "code": "W05885", "name": "Cao Thị Hiền", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_200_W05887", "stt": 200, "code": "W05887", "name": "Nguyễn Thị Vinh", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_201_W05889", "stt": 201, "code": "W05889", "name": "Nguyễn Thị Thanh Huệ", "dept": "Prod 3", "department": "Production 3", "shop": "Machining", "group": "", "note": ""}, {"id": "Prod 3_202_W00177", "stt": 202, "code": "W00177", "name": "Đinh Văn Sơn", "dept": "Prod 3", "department": "Production 3", "shop": "Melting", "group": "", "note": ""}, {"id": "Prod 3_203_W00207", "stt": 203, "code": "W00207", "name": "Nguyễn Mạnh Hùng", "dept": "Prod 3", "department": "Production 3", "shop": "Melting", "group": "", "note": ""}, {"id": "Prod 3_204_W00247", "stt": 204, "code": "W00247", "name": "Nguyễn Quang Phú", "dept": "Prod 3", "department": "Production 3", "shop": "Melting", "group": "", "note": ""}, {"id": "Prod 3_205_W00275", "stt": 205, "code": "W00275", "name": "Nguyễn Thị Nhài", "dept": "Prod 3", "department": "Production 3", "shop": "Melting", "group": "", "note": ""}, {"id": "Prod 3_206_W00722", "stt": 206, "code": "W00722", "name": "Đỗ Văn Hùng", "dept": "Prod 3", "department": "Production 3", "shop": "Melting", "group": "", "note": ""}, {"id": "Prod 3_207_W01035", "stt": 207, "code": "W01035", "name": "Nguyễn Văn Linh", "dept": "Prod 3", "department": "Production 3", "shop": "Melting", "group": "", "note": ""}, {"id": "Prod 3_208_W01156", "stt": 208, "code": "W01156", "name": "Nguyễn Văn Linh", "dept": "Prod 3", "department": "Production 3", "shop": "Melting", "group": "", "note": ""}, {"id": "Prod 3_209_W01161", "stt": 209, "code": "W01161", "name": "Dương Thanh Hoà", "dept": "Prod 3", "department": "Production 3", "shop": "Melting", "group": "", "note": ""}, {"id": "Prod 3_210_W01163", "stt": 210, "code": "W01163", "name": "Nguyễn Văn Ngà", "dept": "Prod 3", "department": "Production 3", "shop": "Melting", "group": "", "note": ""}, {"id": "Prod 3_211_W01426", "stt": 211, "code": "W01426", "name": "Nguyễn Văn Chiến", "dept": "Prod 3", "department": "Production 3", "shop": "Melting", "group": "", "note": ""}, {"id": "Prod 3_212_W01689", "stt": 212, "code": "W01689", "name": "Lưu Văn Ngọc", "dept": "Prod 3", "department": "Production 3", "shop": "Melting", "group": "", "note": ""}, {"id": "Prod 3_213_W02073", "stt": 213, "code": "W02073", "name": "Trần Văn Hải", "dept": "Prod 3", "department": "Production 3", "shop": "Melting", "group": "", "note": ""}, {"id": "Prod 3_214_W02835", "stt": 214, "code": "W02835", "name": "Trần Văn Hải", "dept": "Prod 3", "department": "Production 3", "shop": "Melting", "group": "", "note": ""}, {"id": "Prod 3_215_W03989", "stt": 215, "code": "W03989", "name": "Trần Văn Nam", "dept": "Prod 3", "department": "Production 3", "shop": "Melting", "group": "", "note": ""}, {"id": "Prod 3_216_W04763", "stt": 216, "code": "W04763", "name": "Lê Xuân Oai", "dept": "Prod 3", "department": "Production 3", "shop": "Melting", "group": "", "note": ""}, {"id": "Prod 3_217_W05416", "stt": 217, "code": "W05416", "name": "Lưu Văn Sáng", "dept": "Prod 3", "department": "Production 3", "shop": "Melting", "group": "", "note": ""}, {"id": "Prod 3_218_W00064", "stt": 218, "code": "W00064", "name": "Nguyễn Tiến Phúc", "dept": "Prod 3", "department": "Production 3", "shop": "Mold Maintenance", "group": "", "note": ""}, {"id": "Prod 3_219_W00230", "stt": 219, "code": "W00230", "name": "Trần Xuân Thiện", "dept": "Prod 3", "department": "Production 3", "shop": "Mold Maintenance", "group": "", "note": ""}, {"id": "Prod 3_220_W00689", "stt": 220, "code": "W00689", "name": "Đỗ Văn Dũng", "dept": "Prod 3", "department": "Production 3", "shop": "Mold Maintenance", "group": "", "note": ""}, {"id": "Prod 3_221_W01075", "stt": 221, "code": "W01075", "name": "Nguyễn Thành Trung", "dept": "Prod 3", "department": "Production 3", "shop": "Mold Maintenance", "group": "", "note": ""}, {"id": "Prod 3_222_W01216", "stt": 222, "code": "W01216", "name": "Nguyễn Văn Bình", "dept": "Prod 3", "department": "Production 3", "shop": "Mold Maintenance", "group": "", "note": ""}, {"id": "Prod 3_223_W01425", "stt": 223, "code": "W01425", "name": "Nguyễn Quý Cao", "dept": "Prod 3", "department": "Production 3", "shop": "Mold Maintenance", "group": "", "note": ""}, {"id": "Prod 3_224_W01598", "stt": 224, "code": "W01598", "name": "Nguyễn Thế Trung", "dept": "Prod 3", "department": "Production 3", "shop": "Mold Maintenance", "group": "", "note": ""}, {"id": "Prod 3_225_W02211", "stt": 225, "code": "W02211", "name": "Phạm Văn Lượng", "dept": "Prod 3", "department": "Production 3", "shop": "Mold Maintenance", "group": "", "note": ""}, {"id": "Prod 3_226_W02584", "stt": 226, "code": "W02584", "name": "Hoàng Văn Phong", "dept": "Prod 3", "department": "Production 3", "shop": "Mold Maintenance", "group": "", "note": ""}, {"id": "Prod 3_227_W03049", "stt": 227, "code": "W03049", "name": "Trần Văn Hưng", "dept": "Prod 3", "department": "Production 3", "shop": "Mold Maintenance", "group": "", "note": ""}, {"id": "Prod 3_228_W03242", "stt": 228, "code": "W03242", "name": "Bùi Đức Lộc", "dept": "Prod 3", "department": "Production 3", "shop": "Mold Maintenance", "group": "", "note": ""}, {"id": "Prod 3_229_W03905", "stt": 229, "code": "W03905", "name": "Đỗ Đăng Đà", "dept": "Prod 3", "department": "Production 3", "shop": "Mold Maintenance", "group": "", "note": ""}, {"id": "Prod 3_230_W04971", "stt": 230, "code": "W04971", "name": "Đỗ Đăng Hậu", "dept": "Prod 3", "department": "Production 3", "shop": "Mold Maintenance", "group": "", "note": ""}, {"id": "Prod 3_231_W04976", "stt": 231, "code": "W04976", "name": "Lê Quang Hùng", "dept": "Prod 3", "department": "Production 3", "shop": "Mold Maintenance", "group": "", "note": ""}, {"id": "Prod 3_232_W05226", "stt": 232, "code": "W05226", "name": "Đỗ Đăng Thanh", "dept": "Prod 3", "department": "Production 3", "shop": "Mold Maintenance", "group": "", "note": ""}, {"id": "Prod 3_233_W05558", "stt": 233, "code": "W05558", "name": "Nguyễn Đức Thành", "dept": "Prod 3", "department": "Production 3", "shop": "Mold Maintenance", "group": "", "note": ""}, {"id": "Prod 3_234_W05561", "stt": 234, "code": "W05561", "name": "Đỗ Phương Tuyến", "dept": "Prod 3", "department": "Production 3", "shop": "Mold Maintenance", "group": "", "note": ""}, {"id": "Prod 3_235_W05698", "stt": 235, "code": "W05698", "name": "Trần Văn Trung", "dept": "Prod 3", "department": "Production 3", "shop": "Mold Maintenance", "group": "", "note": ""}, {"id": "Prod 3_236_W05762", "stt": 236, "code": "W05762", "name": "Nguyễn Chí Minh", "dept": "Prod 3", "department": "Production 3", "shop": "Mold Maintenance", "group": "", "note": ""}, {"id": "Prod 3_237_S00027", "stt": 237, "code": "S00027", "name": "Lê Văn Bắc", "dept": "Prod 3", "department": "Production 3", "shop": "Officer", "group": "", "note": ""}, {"id": "Prod 3_238_S00062", "stt": 238, "code": "S00062", "name": "Nguyễn Văn Quỳnh", "dept": "Prod 3", "department": "Production 3", "shop": "Officer", "group": "", "note": ""}, {"id": "Prod 3_239_S00068", "stt": 239, "code": "S00068", "name": "Phạm Như Quỳnh", "dept": "Prod 3", "department": "Production 3", "shop": "Officer", "group": "", "note": ""}, {"id": "Prod 3_240_S00096", "stt": 240, "code": "S00096", "name": "Nguyễn Thị Thu Hoài", "dept": "Prod 3", "department": "Production 3", "shop": "Officer", "group": "", "note": ""}, {"id": "Prod 3_241_S00108", "stt": 241, "code": "S00108", "name": "Đỗ Phi Hằng", "dept": "Prod 3", "department": "Production 3", "shop": "Officer", "group": "", "note": ""}, {"id": "Prod 3_242_S00111", "stt": 242, "code": "S00111", "name": "Mạc Tư Khoa", "dept": "Prod 3", "department": "Production 3", "shop": "Officer", "group": "", "note": ""}, {"id": "Prod 3_243_S00215", "stt": 243, "code": "S00215", "name": "Nguyễn Thùy Dương", "dept": "Prod 3", "department": "Production 3", "shop": "Officer", "group": "", "note": ""}, {"id": "Prod 3_244_W00133", "stt": 244, "code": "W00133", "name": "Đặng Thu Thuỳ", "dept": "Prod 3", "department": "Production 3", "shop": "Officer", "group": "", "note": ""}, {"id": "Prod 3_245_W00349", "stt": 245, "code": "W00349", "name": "Nguyễn Thị Chiên", "dept": "Prod 3", "department": "Production 3", "shop": "Officer", "group": "", "note": ""}, {"id": "Prod 3_246_W01086", "stt": 246, "code": "W01086", "name": "Vũ Thị Xuân", "dept": "Prod 3", "department": "Production 3", "shop": "Officer", "group": "", "note": ""}, {"id": "Prod 3_247_W01994", "stt": 247, "code": "W01994", "name": "Nguyễn Thị Duyên", "dept": "Prod 3", "department": "Production 3", "shop": "Officer", "group": "", "note": ""}, {"id": "Prod 3_248_W03266", "stt": 248, "code": "W03266", "name": "Nguyễn Thị Thanh Huyền", "dept": "Prod 3", "department": "Production 3", "shop": "Officer", "group": "", "note": ""}, {"id": "Prod 3_249_W04801", "stt": 249, "code": "W04801", "name": "Nguyễn Thị Thu Thúy", "dept": "Prod 3", "department": "Production 3", "shop": "Officer", "group": "", "note": ""}, {"id": "Prod 3_250_W05492", "stt": 250, "code": "W05492", "name": "Nguyễn Thị Hường", "dept": "Prod 3", "department": "Production 3", "shop": "Officer", "group": "", "note": ""}, {"id": "Prod 3_251_W05676", "stt": 251, "code": "W05676", "name": "Nguyễn Thuỳ Linh", "dept": "Prod 3", "department": "Production 3", "shop": "Officer", "group": "", "note": ""}, {"id": "Prod 3_252_W00025", "stt": 252, "code": "W00025", "name": "Nguyễn Đăng Hường", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_253_W00150", "stt": 253, "code": "W00150", "name": "Nguyễn Thị Hường", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_254_W00167", "stt": 254, "code": "W00167", "name": "Trần Thị Mai Hương", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_255_W00572", "stt": 255, "code": "W00572", "name": "Hà Văn Thuận", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_256_W00628", "stt": 256, "code": "W00628", "name": "Công Phương Thọ", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_257_W00697", "stt": 257, "code": "W00697", "name": "Trần Văn Huy", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_258_W00789", "stt": 258, "code": "W00789", "name": "Phan Thế Hùng", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_259_W01034", "stt": 259, "code": "W01034", "name": "Trần Thị Liên", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_260_W01059", "stt": 260, "code": "W01059", "name": "Trần Thị Thảo", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_261_W01073", "stt": 261, "code": "W01073", "name": "Phạm Quốc Trường", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_262_W01092", "stt": 262, "code": "W01092", "name": "Nguyễn Thị Thu Trang", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_263_W01097", "stt": 263, "code": "W01097", "name": "Hà Ngọc Tân", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_264_W01302", "stt": 264, "code": "W01302", "name": "Nguyễn Thị Duyên", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_265_W01373", "stt": 265, "code": "W01373", "name": "Nguyễn Thị Vân", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_266_W01389", "stt": 266, "code": "W01389", "name": "Nguyễn Văn Huân", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_267_W01408", "stt": 267, "code": "W01408", "name": "Hán Xuân Trường", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_268_W01577", "stt": 268, "code": "W01577", "name": "Phan Đức Lợi", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_269_W01581", "stt": 269, "code": "W01581", "name": "Phạm Thị Nguyên", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_270_W01601", "stt": 270, "code": "W01601", "name": "Nguyễn Văn Đông", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_271_W01606", "stt": 271, "code": "W01606", "name": "Nguyễn Huy Nam", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_272_W01615", "stt": 272, "code": "W01615", "name": "Nguyễn Duy Bình", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_273_W01665", "stt": 273, "code": "W01665", "name": "Trần Thị Thu Thủy", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_274_W01670", "stt": 274, "code": "W01670", "name": "Phạm Thị Thu", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_275_W01700", "stt": 275, "code": "W01700", "name": "Vương Đình Tâm", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_276_W02041", "stt": 276, "code": "W02041", "name": "Nguyễn Thị Lan", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_277_W02098", "stt": 277, "code": "W02098", "name": "Trần văn Nam", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_278_W02176", "stt": 278, "code": "W02176", "name": "Vũ Thu Hà", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_279_W02180", "stt": 279, "code": "W02180", "name": "Tạ Thị Huyền Chang", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_280_W02285", "stt": 280, "code": "W02285", "name": "Vũ Thị Hoa", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_281_W02337", "stt": 281, "code": "W02337", "name": "Dương Ngô Tân", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_282_W02348", "stt": 282, "code": "W02348", "name": "Nguyễn Bá Duẩn", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_283_W02349", "stt": 283, "code": "W02349", "name": "Hoàng Văn Phúc", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_284_W02543", "stt": 284, "code": "W02543", "name": "Nguyễn Giang Đông", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_285_W02606", "stt": 285, "code": "W02606", "name": "Hoàng Thị Hòa", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_286_W02878", "stt": 286, "code": "W02878", "name": "Lê Hoàng Liên", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_287_W03134", "stt": 287, "code": "W03134", "name": "Hoàng Văn Sáng", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_288_W03221", "stt": 288, "code": "W03221", "name": "Nguyễn Xuân Đại", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_289_W03250", "stt": 289, "code": "W03250", "name": "Hoàng Văn Thành", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_290_W03285", "stt": 290, "code": "W03285", "name": "Nguyễn Văn Thành", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_291_W03440", "stt": 291, "code": "W03440", "name": "Triệu Ngọc Lượng", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_292_W03499", "stt": 292, "code": "W03499", "name": "Trương Trọng Tĩnh", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_293_W03650", "stt": 293, "code": "W03650", "name": "Nguyễn Thị Liên", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_294_W03687", "stt": 294, "code": "W03687", "name": "Lưu Văn Hùng", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_295_W03808", "stt": 295, "code": "W03808", "name": "Bùi Tuấn Anh", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_296_W04141", "stt": 296, "code": "W04141", "name": "Nguyễn Quốc Tuấn", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_297_W04488", "stt": 297, "code": "W04488", "name": "Đỗ Duy Chung", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_298_W04546", "stt": 298, "code": "W04546", "name": "Ngô Đăng Khánh Toàn", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_299_W04812", "stt": 299, "code": "W04812", "name": "Đỗ Văn Chính", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_300_W04869", "stt": 300, "code": "W04869", "name": "Nguyễn Văn Thiện", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_301_W05104", "stt": 301, "code": "W05104", "name": "Nguyễn Cao Cường", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_302_W05130", "stt": 302, "code": "W05130", "name": "Đỗ Đăng Mầu", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_303_W05237", "stt": 303, "code": "W05237", "name": "Nguyễn Công Trường", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_304_W05283", "stt": 304, "code": "W05283", "name": "Nguyễn Văn Dũng", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_305_W05347", "stt": 305, "code": "W05347", "name": "Trần Văn Hiển", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_306_W05355", "stt": 306, "code": "W05355", "name": "Hoàng Vinh Phúc", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_307_W05474", "stt": 307, "code": "W05474", "name": "Nguyễn Văn Xinh", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_308_W05478", "stt": 308, "code": "W05478", "name": "Nguyễn Dương Bình", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_309_W05482", "stt": 309, "code": "W05482", "name": "Hà Thu Trang", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_310_W05491", "stt": 310, "code": "W05491", "name": "Nguyễn Tuấn Anh", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_311_W05619", "stt": 311, "code": "W05619", "name": "Nguyễn Văn Bắc", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_312_W05674", "stt": 312, "code": "W05674", "name": "Nguyễn Thị Thùy Dung", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_313_W05756", "stt": 313, "code": "W05756", "name": "Đỗ Thị Trang", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_314_W05760", "stt": 314, "code": "W05760", "name": "Đỗ Hồng Sơn", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_315_W05761", "stt": 315, "code": "W05761", "name": "Đồng Văn Ngọc", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_316_W05765", "stt": 316, "code": "W05765", "name": "Nguyễn Văn Hưng", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_317_W05771", "stt": 317, "code": "W05771", "name": "Trần Văn Dần", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_318_W05791", "stt": 318, "code": "W05791", "name": "Phạm Hồng Thanh", "dept": "Prod 3", "department": "Production 3", "shop": "Painting", "group": "", "note": ""}, {"id": "Prod 3_319_W00057", "stt": 319, "code": "W00057", "name": "Lê Thị Diễm", "dept": "Prod 3", "department": "Production 3", "shop": "Pinstripe", "group": "", "note": ""}, {"id": "Prod 3_320_W00127", "stt": 320, "code": "W00127", "name": "Phạm Văn Tư", "dept": "Prod 3", "department": "Production 3", "shop": "Pinstripe", "group": "", "note": ""}, {"id": "Prod 3_321_W00146", "stt": 321, "code": "W00146", "name": "Nguyễn Thị Chinh", "dept": "Prod 3", "department": "Production 3", "shop": "Pinstripe", "group": "", "note": ""}, {"id": "Prod 3_322_W00258", "stt": 322, "code": "W00258", "name": "Vũ Thị Hương", "dept": "Prod 3", "department": "Production 3", "shop": "Pinstripe", "group": "", "note": ""}, {"id": "Prod 3_323_W01066", "stt": 323, "code": "W01066", "name": "Nguyễn Thị Thược", "dept": "Prod 3", "department": "Production 3", "shop": "Pinstripe", "group": "", "note": ""}, {"id": "Prod 3_324_W01101", "stt": 324, "code": "W01101", "name": "Hà Tài Tư", "dept": "Prod 3", "department": "Production 3", "shop": "Pinstripe", "group": "", "note": ""}, {"id": "Prod 3_325_W01171", "stt": 325, "code": "W01171", "name": "Nguyễn Xuân Quang", "dept": "Prod 3", "department": "Production 3", "shop": "Pinstripe", "group": "", "note": ""}, {"id": "Prod 3_326_W01343", "stt": 326, "code": "W01343", "name": "Nguyễn Văn Công", "dept": "Prod 3", "department": "Production 3", "shop": "Pinstripe", "group": "", "note": ""}, {"id": "Prod 3_327_W01355", "stt": 327, "code": "W01355", "name": "Trương Thị Lý", "dept": "Prod 3", "department": "Production 3", "shop": "Pinstripe", "group": "", "note": ""}, {"id": "Prod 3_328_W01421", "stt": 328, "code": "W01421", "name": "Nguyễn Thị Hồng Anh", "dept": "Prod 3", "department": "Production 3", "shop": "Pinstripe", "group": "", "note": ""}, {"id": "Prod 3_329_W01695", "stt": 329, "code": "W01695", "name": "Triệu Quang Hồng", "dept": "Prod 3", "department": "Production 3", "shop": "Pinstripe", "group": "", "note": ""}, {"id": "Prod 3_330_W01760", "stt": 330, "code": "W01760", "name": "Nguyễn Đắc Quỳnh", "dept": "Prod 3", "department": "Production 3", "shop": "Pinstripe", "group": "", "note": ""}, {"id": "Prod 3_331_W02003", "stt": 331, "code": "W02003", "name": "Phạm Thị Thảo", "dept": "Prod 3", "department": "Production 3", "shop": "Pinstripe", "group": "", "note": ""}, {"id": "Prod 3_332_W02072", "stt": 332, "code": "W02072", "name": "Lê Đình Việt", "dept": "Prod 3", "department": "Production 3", "shop": "Pinstripe", "group": "", "note": ""}, {"id": "Prod 3_333_W02165", "stt": 333, "code": "W02165", "name": "Đàm Thị Kim Thúy", "dept": "Prod 3", "department": "Production 3", "shop": "Pinstripe", "group": "", "note": ""}, {"id": "Prod 3_334_W02192", "stt": 334, "code": "W02192", "name": "Dương Thị Lan", "dept": "Prod 3", "department": "Production 3", "shop": "Pinstripe", "group": "", "note": ""}, {"id": "Prod 3_335_W02435", "stt": 335, "code": "W02435", "name": "Trần Thị Hương", "dept": "Prod 3", "department": "Production 3", "shop": "Pinstripe", "group": "", "note": ""}, {"id": "Prod 3_336_W02761", "stt": 336, "code": "W02761", "name": "Nguyễn Đình Đông", "dept": "Prod 3", "department": "Production 3", "shop": "Pinstripe", "group": "", "note": ""}, {"id": "Prod 3_337_W02828", "stt": 337, "code": "W02828", "name": "Đinh Thị Phượng", "dept": "Prod 3", "department": "Production 3", "shop": "Pinstripe", "group": "", "note": ""}, {"id": "Prod 3_338_W02937", "stt": 338, "code": "W02937", "name": "Phạm Ngọc Lý", "dept": "Prod 3", "department": "Production 3", "shop": "Pinstripe", "group": "", "note": ""}, {"id": "Prod 3_339_W03008", "stt": 339, "code": "W03008", "name": "Phạm Ngọc Hùng", "dept": "Prod 3", "department": "Production 3", "shop": "Pinstripe", "group": "", "note": ""}, {"id": "Prod 3_340_W03230", "stt": 340, "code": "W03230", "name": "Lương Quang Hiển", "dept": "Prod 3", "department": "Production 3", "shop": "Pinstripe", "group": "", "note": ""}, {"id": "Prod 3_341_W03247", "stt": 341, "code": "W03247", "name": "Nguyễn Minh Phụng", "dept": "Prod 3", "department": "Production 3", "shop": "Pinstripe", "group": "", "note": ""}, {"id": "Prod 3_342_W03394", "stt": 342, "code": "W03394", "name": "Hoàng Thị Hiền", "dept": "Prod 3", "department": "Production 3", "shop": "Pinstripe", "group": "", "note": ""}, {"id": "Prod 3_343_W04534", "stt": 343, "code": "W04534", "name": "Đào Duy Hải", "dept": "Prod 3", "department": "Production 3", "shop": "Pinstripe", "group": "", "note": ""}, {"id": "Prod 3_344_W04608", "stt": 344, "code": "W04608", "name": "Bùi Thanh Lý", "dept": "Prod 3", "department": "Production 3", "shop": "Pinstripe", "group": "", "note": ""}, {"id": "Prod 3_345_W04687", "stt": 345, "code": "W04687", "name": "Trương Xuân Thi", "dept": "Prod 3", "department": "Production 3", "shop": "Pinstripe", "group": "", "note": ""}, {"id": "Prod 3_346_W04987", "stt": 346, "code": "W04987", "name": "Hà Đình Linh", "dept": "Prod 3", "department": "Production 3", "shop": "Pinstripe", "group": "", "note": ""}, {"id": "Prod 3_347_W05000", "stt": 347, "code": "W05000", "name": "Lê Thị Oanh", "dept": "Prod 3", "department": "Production 3", "shop": "Pinstripe", "group": "", "note": ""}, {"id": "Prod 3_348_W05121", "stt": 348, "code": "W05121", "name": "Nguyễn Quang Huy", "dept": "Prod 3", "department": "Production 3", "shop": "Pinstripe", "group": "", "note": ""}, {"id": "Prod 3_349_W05125", "stt": 349, "code": "W05125", "name": "Trần Thị Nhật Lệ", "dept": "Prod 3", "department": "Production 3", "shop": "Pinstripe", "group": "", "note": ""}, {"id": "Prod 3_350_W05174", "stt": 350, "code": "W05174", "name": "Đỗ Văn Bảo", "dept": "Prod 3", "department": "Production 3", "shop": "Pinstripe", "group": "", "note": ""}, {"id": "Prod 3_351_W05287", "stt": 351, "code": "W05287", "name": "Dương Yến Hạnh", "dept": "Prod 3", "department": "Production 3", "shop": "Pinstripe", "group": "", "note": ""}, {"id": "Prod 3_352_W05297", "stt": 352, "code": "W05297", "name": "Đào Văn Mạnh Huỳnh", "dept": "Prod 3", "department": "Production 3", "shop": "Pinstripe", "group": "", "note": ""}, {"id": "Prod 3_353_W05307", "stt": 353, "code": "W05307", "name": "Trần Quang Nhã", "dept": "Prod 3", "department": "Production 3", "shop": "Pinstripe", "group": "", "note": ""}, {"id": "Prod 3_354_W05311", "stt": 354, "code": "W05311", "name": "Nguyễn Thị Phượng", "dept": "Prod 3", "department": "Production 3", "shop": "Pinstripe", "group": "", "note": ""}, {"id": "Prod 3_355_W05338", "stt": 355, "code": "W05338", "name": "Phạm Văn Thủy", "dept": "Prod 3", "department": "Production 3", "shop": "Pinstripe", "group": "", "note": ""}, {"id": "Prod 3_356_W05352", "stt": 356, "code": "W05352", "name": "Đỗ Quang Lĩnh", "dept": "Prod 3", "department": "Production 3", "shop": "Pinstripe", "group": "", "note": ""}, {"id": "Prod 3_357_W05391", "stt": 357, "code": "W05391", "name": "Nguyễn Văn Thăng", "dept": "Prod 3", "department": "Production 3", "shop": "Pinstripe", "group": "", "note": ""}, {"id": "Prod 3_358_W05466", "stt": 358, "code": "W05466", "name": "Hà Văn Thịnh", "dept": "Prod 3", "department": "Production 3", "shop": "Pinstripe", "group": "", "note": ""}, {"id": "Prod 3_359_W05480", "stt": 359, "code": "W05480", "name": "Đỗ Thị Hải Yến", "dept": "Prod 3", "department": "Production 3", "shop": "Pinstripe", "group": "", "note": ""}, {"id": "Prod 3_360_W05484", "stt": 360, "code": "W05484", "name": "Hoàng Chí Thiện", "dept": "Prod 3", "department": "Production 3", "shop": "Pinstripe", "group": "", "note": ""}, {"id": "Prod 3_361_W05490", "stt": 361, "code": "W05490", "name": "Đoàn Thị Trang", "dept": "Prod 3", "department": "Production 3", "shop": "Pinstripe", "group": "", "note": ""}, {"id": "Prod 3_362_W05517", "stt": 362, "code": "W05517", "name": "Nguyễn Thị Ánh Tuyết", "dept": "Prod 3", "department": "Production 3", "shop": "Pinstripe", "group": "", "note": ""}, {"id": "Prod 3_363_W05544", "stt": 363, "code": "W05544", "name": "Nguyễn Bá Trường", "dept": "Prod 3", "department": "Production 3", "shop": "Pinstripe", "group": "", "note": ""}, {"id": "Prod 3_364_W05559", "stt": 364, "code": "W05559", "name": "Nguyễn Trung Tính", "dept": "Prod 3", "department": "Production 3", "shop": "Pinstripe", "group": "", "note": ""}, {"id": "Prod 3_365_W05563", "stt": 365, "code": "W05563", "name": "Bùi Thị Nga", "dept": "Prod 3", "department": "Production 3", "shop": "Pinstripe", "group": "", "note": ""}, {"id": "Prod 3_366_W05679", "stt": 366, "code": "W05679", "name": "Nguyễn Văn Trường", "dept": "Prod 3", "department": "Production 3", "shop": "Pinstripe", "group": "", "note": ""}, {"id": "Prod 3_367_W05809", "stt": 367, "code": "W05809", "name": "Ngô Thị Quỳnh", "dept": "Prod 3", "department": "Production 3", "shop": "Pinstripe", "group": "", "note": ""}, {"id": "Prod 3_368_W05845", "stt": 368, "code": "W05845", "name": "Đỗ Hồng Kiên", "dept": "Prod 3", "department": "Production 3", "shop": "Pinstripe", "group": "", "note": ""}, {"id": "Prod 3_369_W05853", "stt": 369, "code": "W05853", "name": "Đỗ Thị Thảo", "dept": "Prod 3", "department": "Production 3", "shop": "Pinstripe", "group": "", "note": ""}, {"id": "Prod 3_370_W05882", "stt": 370, "code": "W05882", "name": "Ngô Văn Út", "dept": "Prod 3", "department": "Production 3", "shop": "Pinstripe", "group": "", "note": ""}, {"id": "Prod 3_371_W05884", "stt": 371, "code": "W05884", "name": "Nguyễn Thị Tuyến", "dept": "Prod 3", "department": "Production 3", "shop": "Pinstripe", "group": "", "note": ""}, {"id": "Prod 3_372_W05886", "stt": 372, "code": "W05886", "name": "Trần Thị Hà", "dept": "Prod 3", "department": "Production 3", "shop": "Pinstripe", "group": "", "note": ""}, {"id": "Prod 3_373_W00031", "stt": 373, "code": "W00031", "name": "Trần Huy Tiến", "dept": "Prod 3", "department": "Production 3", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 3_374_W00058", "stt": 374, "code": "W00058", "name": "Phan Ngọc Sáng", "dept": "Prod 3", "department": "Production 3", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 3_375_W00087", "stt": 375, "code": "W00087", "name": "Đỗ Thị Hà", "dept": "Prod 3", "department": "Production 3", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 3_376_W00155", "stt": 376, "code": "W00155", "name": "Nguyễn Thị Soa", "dept": "Prod 3", "department": "Production 3", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 3_377_W00159", "stt": 377, "code": "W00159", "name": "Nguyễn Thị Thu Hoài", "dept": "Prod 3", "department": "Production 3", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 3_378_W00164", "stt": 378, "code": "W00164", "name": "Phan Thị Hồng Nhung", "dept": "Prod 3", "department": "Production 3", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 3_379_W00288", "stt": 379, "code": "W00288", "name": "Phùng Thị Hồng Hạnh", "dept": "Prod 3", "department": "Production 3", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 3_380_W00407", "stt": 380, "code": "W00407", "name": "Tạ Ngọc Thảo", "dept": "Prod 3", "department": "Production 3", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 3_381_W00413", "stt": 381, "code": "W00413", "name": "Trần Văn Nam", "dept": "Prod 3", "department": "Production 3", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 3_382_W00505", "stt": 382, "code": "W00505", "name": "Nguyễn Đình Chiến", "dept": "Prod 3", "department": "Production 3", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 3_383_W01038", "stt": 383, "code": "W01038", "name": "Nguyễn Thị Lý", "dept": "Prod 3", "department": "Production 3", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 3_384_W01043", "stt": 384, "code": "W01043", "name": "Nguyễn Thị Nga", "dept": "Prod 3", "department": "Production 3", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 3_385_W01068", "stt": 385, "code": "W01068", "name": "Dương Văn Thể", "dept": "Prod 3", "department": "Production 3", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 3_386_W01093", "stt": 386, "code": "W01093", "name": "Trần Thị Phúc", "dept": "Prod 3", "department": "Production 3", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 3_387_W01137", "stt": 387, "code": "W01137", "name": "Nguyễn Lê Lịu", "dept": "Prod 3", "department": "Production 3", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 3_388_W01149", "stt": 388, "code": "W01149", "name": "Nguyễn Thị Vụ", "dept": "Prod 3", "department": "Production 3", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 3_389_W01204", "stt": 389, "code": "W01204", "name": "Nguyễn Đức Bắc", "dept": "Prod 3", "department": "Production 3", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 3_390_W01329", "stt": 390, "code": "W01329", "name": "Lương Văn Nam", "dept": "Prod 3", "department": "Production 3", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 3_391_W01392", "stt": 391, "code": "W01392", "name": "Trương Văn Khánh", "dept": "Prod 3", "department": "Production 3", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 3_392_W01397", "stt": 392, "code": "W01397", "name": "Nguyễn Thị Minh", "dept": "Prod 3", "department": "Production 3", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 3_393_W01667", "stt": 393, "code": "W01667", "name": "Lê Thị Thắm", "dept": "Prod 3", "department": "Production 3", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 3_394_W01815", "stt": 394, "code": "W01815", "name": "Nguyễn Thị Thúy", "dept": "Prod 3", "department": "Production 3", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 3_395_W02286", "stt": 395, "code": "W02286", "name": "Vương Thị Vị", "dept": "Prod 3", "department": "Production 3", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 3_396_W02431", "stt": 396, "code": "W02431", "name": "Nguyễn Thị Hiền", "dept": "Prod 3", "department": "Production 3", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 3_397_W02557", "stt": 397, "code": "W02557", "name": "Nguyễn Thị Hưng", "dept": "Prod 3", "department": "Production 3", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 3_398_W03364", "stt": 398, "code": "W03364", "name": "Nguyễn Ngọc Khánh", "dept": "Prod 3", "department": "Production 3", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 3_399_W03731", "stt": 399, "code": "W03731", "name": "Nguyễn Thế Anh", "dept": "Prod 3", "department": "Production 3", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 3_400_W04082", "stt": 400, "code": "W04082", "name": "Nguyễn Thị Hạnh", "dept": "Prod 3", "department": "Production 3", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 3_401_W04248", "stt": 401, "code": "W04248", "name": "Hoàng Thị An", "dept": "Prod 3", "department": "Production 3", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 3_402_W04543", "stt": 402, "code": "W04543", "name": "Lại Thị Huyền", "dept": "Prod 3", "department": "Production 3", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 3_403_W04676", "stt": 403, "code": "W04676", "name": "Đỗ Đăng Hiền", "dept": "Prod 3", "department": "Production 3", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 3_404_W04793", "stt": 404, "code": "W04793", "name": "Phạm Thị Thanh Hòa", "dept": "Prod 3", "department": "Production 3", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 3_405_W04985", "stt": 405, "code": "W04985", "name": "Nguyễn Thị Lan", "dept": "Prod 3", "department": "Production 3", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 3_406_W05071", "stt": 406, "code": "W05071", "name": "Lê Thị Thanh Thúy", "dept": "Prod 3", "department": "Production 3", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 3_407_W05221", "stt": 407, "code": "W05221", "name": "Nghiêm Thị Hồng Oanh", "dept": "Prod 3", "department": "Production 3", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 3_408_W05327", "stt": 408, "code": "W05327", "name": "Nguyễn Văn Sang", "dept": "Prod 3", "department": "Production 3", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 3_409_W05330", "stt": 409, "code": "W05330", "name": "Nguyễn Thị Minh Tâm", "dept": "Prod 3", "department": "Production 3", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 3_410_W05610", "stt": 410, "code": "W05610", "name": "Nguyễn Thị Bộ", "dept": "Prod 3", "department": "Production 3", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 3_411_W05691", "stt": 411, "code": "W05691", "name": "Trần Thị Bắc", "dept": "Prod 3", "department": "Production 3", "shop": "QC", "group": "", "note": ""}, {"id": "Prod 3_412_W05888", "stt": 412, "code": "W05888", "name": "Nguyễn Thị Nhung", "dept": "Prod 3", "department": "Production 3", "shop": "QC", "group": "", "note": ""}, {"id": "MT_1_S00286", "stt": 1, "code": "S00286", "name": "Nguyễn Hải Nam", "dept": "MT", "department": "Maintenance", "shop": "", "group": "", "note": ""}, {"id": "MT_2_S00097", "stt": 2, "code": "S00097", "name": "Nguyễn Hữu Thế", "dept": "MT", "department": "Maintenance", "shop": "Prod 1-3 & Corporate", "group": "", "note": ""}, {"id": "MT_3_S00099", "stt": 3, "code": "S00099", "name": "Lã Ngọc Thanh", "dept": "MT", "department": "Maintenance", "shop": "Prod 1-3 & Corporate", "group": "", "note": ""}, {"id": "MT_4_S00141", "stt": 4, "code": "S00141", "name": "Nguyễn Quang Anh", "dept": "MT", "department": "Maintenance", "shop": "Prod 1-3 & Corporate", "group": "", "note": ""}, {"id": "MT_5_S00195", "stt": 5, "code": "S00195", "name": "Ngô Quang Trường", "dept": "MT", "department": "Maintenance", "shop": "Prod 1-3 & Corporate", "group": "", "note": ""}, {"id": "MT_6_S00224", "stt": 6, "code": "S00224", "name": "Đặng Phương Nam", "dept": "MT", "department": "Maintenance", "shop": "Prod 1-3 & Corporate", "group": "", "note": ""}, {"id": "MT_7_S00267", "stt": 7, "code": "S00267", "name": "Nguyễn Huy Long", "dept": "MT", "department": "Maintenance", "shop": "Prod 1-3 & Corporate", "group": "", "note": ""}, {"id": "MT_8_S00080", "stt": 8, "code": "S00080", "name": "Đỗ Văn Bình", "dept": "MT", "department": "Maintenance", "shop": "Prod 2", "group": "", "note": ""}, {"id": "MT_9_S00175", "stt": 9, "code": "S00175", "name": "Đặng Tiến Mạnh", "dept": "MT", "department": "Maintenance", "shop": "Prod 2", "group": "", "note": ""}, {"id": "MT_10_S00176", "stt": 10, "code": "S00176", "name": "Lê Tiến Dũng", "dept": "MT", "department": "Maintenance", "shop": "Prod 2", "group": "", "note": ""}, {"id": "MT_11_S00208", "stt": 11, "code": "S00208", "name": "Ngô Văn Khang", "dept": "MT", "department": "Maintenance", "shop": "Prod 2", "group": "", "note": ""}, {"id": "MT_12_S00266", "stt": 12, "code": "S00266", "name": "Phạm Văn Dân", "dept": "MT", "department": "Maintenance", "shop": "Prod 2", "group": "", "note": ""}, {"id": "MT_13_W00013", "stt": 13, "code": "W00013", "name": "Nguyễn Thành Hiệp", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_14_W00024", "stt": 14, "code": "W00024", "name": "Nguyễn Văn Phúc", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_15_W00027", "stt": 15, "code": "W00027", "name": "Nguyễn Văn Chiến", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_16_W00059", "stt": 16, "code": "W00059", "name": "Nguyễn Văn Hợp", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_17_W00122", "stt": 17, "code": "W00122", "name": "Nguyễn Văn Điểm", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_18_W00252", "stt": 18, "code": "W00252", "name": "Nguyễn Văn Thường", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_19_W00263", "stt": 19, "code": "W00263", "name": "Nguyễn Minh Hoành", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_20_W00384", "stt": 20, "code": "W00384", "name": "Ngô Văn Cường", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_21_W00435", "stt": 21, "code": "W00435", "name": "Nguyễn Xuân Được", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_22_W00483", "stt": 22, "code": "W00483", "name": "Đào Xuân Đại", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_23_W00492", "stt": 23, "code": "W00492", "name": "Đinh Văn Sơn", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_24_W00514", "stt": 24, "code": "W00514", "name": "Nguyễn Huy Thức", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_25_W00519", "stt": 25, "code": "W00519", "name": "Nguyễn Văn Chiến", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_26_W00560", "stt": 26, "code": "W00560", "name": "Lê Bá Lào", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_27_W00580", "stt": 27, "code": "W00580", "name": "Lê Công Huy", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_28_W00616", "stt": 28, "code": "W00616", "name": "Đinh Xuân Thái", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_29_W00635", "stt": 29, "code": "W00635", "name": "Dương Văn Lập", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_30_W00636", "stt": 30, "code": "W00636", "name": "Quách Văn Sơn", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_31_W00649", "stt": 31, "code": "W00649", "name": "Nguyễn Quốc Huy", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_32_W00650", "stt": 32, "code": "W00650", "name": "Nguyễn Minh Vương", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_33_W00663", "stt": 33, "code": "W00663", "name": "Nguyễn Công Luyến", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_34_W00667", "stt": 34, "code": "W00667", "name": "Nguyễn Thế Quang", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_35_W00766", "stt": 35, "code": "W00766", "name": "Nguyễn Thanh Diên", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_36_W00836", "stt": 36, "code": "W00836", "name": "Nguyễn Văn Chính", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_37_W00847", "stt": 37, "code": "W00847", "name": "Lê Văn Phúc", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_38_W00884", "stt": 38, "code": "W00884", "name": "Chu Văn Long", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_39_W01000", "stt": 39, "code": "W01000", "name": "Nguyễn Quang Biển", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_40_W01002", "stt": 40, "code": "W01002", "name": "Nguyễn Văn Ca", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_41_W01030", "stt": 41, "code": "W01030", "name": "Nguyễn Đức Hoan", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_42_W01061", "stt": 42, "code": "W01061", "name": "Vương Xuân Thắng", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_43_W01109", "stt": 43, "code": "W01109", "name": "Trịnh Văn Hoàng", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_44_W01141", "stt": 44, "code": "W01141", "name": "Phạm Trung Kiên", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_45_W01165", "stt": 45, "code": "W01165", "name": "Lê Văn Thắng", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_46_W01169", "stt": 46, "code": "W01169", "name": "Nông Văn Hà", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_47_W01264", "stt": 47, "code": "W01264", "name": "Trần Đức Thịnh", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_48_W01322", "stt": 48, "code": "W01322", "name": "Nguyễn Hồng Kỳ", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_49_W01410", "stt": 49, "code": "W01410", "name": "Trịnh Lâm Tuấn", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_50_W01418", "stt": 50, "code": "W01418", "name": "Lê Văn Điền", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_51_W01434", "stt": 51, "code": "W01434", "name": "Hoàng Văn Hồng", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_52_W01523", "stt": 52, "code": "W01523", "name": "Vũ Quốc Quân", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_53_W01751", "stt": 53, "code": "W01751", "name": "Bùi Văn Luận", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_54_W01903", "stt": 54, "code": "W01903", "name": "Đỗ Văn Hùng", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_55_W01956", "stt": 55, "code": "W01956", "name": "Nguyễn Văn Đức", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_56_W02095", "stt": 56, "code": "W02095", "name": "Nguyễn Văn Quý", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_57_W02125", "stt": 57, "code": "W02125", "name": "Nguyễn Trọng Trường", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_58_W02365", "stt": 58, "code": "W02365", "name": "Đỗ Văn Long", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_59_W02440", "stt": 59, "code": "W02440", "name": "Phạm Tuấn Nhuận", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_60_W02450", "stt": 60, "code": "W02450", "name": "Vi Văn Thành", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_61_W02451", "stt": 61, "code": "W02451", "name": "Nguyễn Hữu Hưng", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_62_W02457", "stt": 62, "code": "W02457", "name": "Nguyễn Duy Hiệu", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_63_W02513", "stt": 63, "code": "W02513", "name": "Phạm Sỹ Ánh", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_64_W02581", "stt": 64, "code": "W02581", "name": "Giáp Văn Quỳnh", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_65_W02890", "stt": 65, "code": "W02890", "name": "Nông Văn Hiếu", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_66_W02902", "stt": 66, "code": "W02902", "name": "Phạm Văn Cử", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_67_W02951", "stt": 67, "code": "W02951", "name": "Đinh Thị Thu Thủy", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_68_W02968", "stt": 68, "code": "W02968", "name": "Hoàng Văn Đạt", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_69_W02996", "stt": 69, "code": "W02996", "name": "Lê Văn Biên", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_70_W03189", "stt": 70, "code": "W03189", "name": "Nông Xuân Khuê", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_71_W03412", "stt": 71, "code": "W03412", "name": "Phạm Văn Dương", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_72_W03417", "stt": 72, "code": "W03417", "name": "Trần Thanh Huyên", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_73_W03955", "stt": 73, "code": "W03955", "name": "Nguyễn Tiến Dũng", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_74_W03974", "stt": 74, "code": "W03974", "name": "Trần Thanh Bình", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_75_W04259", "stt": 75, "code": "W04259", "name": "Lê Thị Hường", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_76_W04480", "stt": 76, "code": "W04480", "name": "Nguyễn Thế Tùng", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_77_W05008", "stt": 77, "code": "W05008", "name": "Nguyễn Kim Tài", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_78_W05072", "stt": 78, "code": "W05072", "name": "Đào Văn Tú", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_79_W05074", "stt": 79, "code": "W05074", "name": "Lã Văn Thanh", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_80_W05080", "stt": 80, "code": "W05080", "name": "Phạm Quang Thắng", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_81_W05081", "stt": 81, "code": "W05081", "name": "Hoàng Quốc Huy", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_82_W05113", "stt": 82, "code": "W05113", "name": "Hoàng Ngọc Hách", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_83_W05124", "stt": 83, "code": "W05124", "name": "Nguyễn Khánh", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_84_W05133", "stt": 84, "code": "W05133", "name": "Nguyễn Văn Nam", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_85_W05245", "stt": 85, "code": "W05245", "name": "Lê Minh Anh", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_86_W05246", "stt": 86, "code": "W05246", "name": "Vũ Thành Chung", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_87_W05247", "stt": 87, "code": "W05247", "name": "Nguyễn Thành Công", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_88_W05252", "stt": 88, "code": "W05252", "name": "Đỗ Văn Hải", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_89_W05253", "stt": 89, "code": "W05253", "name": "Lê Minh Hải", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_90_W05254", "stt": 90, "code": "W05254", "name": "Phạm Xuân Hanh", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_91_W05258", "stt": 91, "code": "W05258", "name": "Nguyễn Trung Kiên", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_92_W05260", "stt": 92, "code": "W05260", "name": "Nguyễn Văn Minh", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_93_W05263", "stt": 93, "code": "W05263", "name": "Lê Hoài Nam", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_94_W05265", "stt": 94, "code": "W05265", "name": "Nguyễn Hải Sơn", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_95_W05269", "stt": 95, "code": "W05269", "name": "Đoàn Văn Thanh", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_96_W05270", "stt": 96, "code": "W05270", "name": "Nguyễn Minh Tiến", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_97_W05320", "stt": 97, "code": "W05320", "name": "Đào Duy Tùng", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_98_W05329", "stt": 98, "code": "W05329", "name": "Nguyễn Văn Sơn", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_99_W05406", "stt": 99, "code": "W05406", "name": "Lương Văn Khanh", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_100_W05445", "stt": 100, "code": "W05445", "name": "Nguyễn Thế Lâm", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "MT_101_W05743", "stt": 101, "code": "W05743", "name": "Nguyễn Văn Mạnh", "dept": "MT", "department": "Maintenance", "shop": "Production", "group": "", "note": ""}, {"id": "Bảo an_1_S00024", "stt": 1, "code": "S00024", "name": "Nguyễn Tiến Dũng", "dept": "Bảo an", "department": "Utility", "shop": "", "group": "", "note": ""}, {"id": "Bảo an_2_S00263", "stt": 2, "code": "S00263", "name": "Đàm Mạnh Tuân", "dept": "Bảo an", "department": "Utility", "shop": "", "group": "", "note": ""}, {"id": "Bảo an_3_S00133", "stt": 3, "code": "S00133", "name": "Phương Thị Huệ", "dept": "Bảo an", "department": "Utility", "shop": "", "group": "", "note": ""}, {"id": "Bảo an_4_S00272", "stt": 4, "code": "S00272", "name": "Đào Thiện Công", "dept": "Bảo an", "department": "Utility", "shop": "", "group": "", "note": ""}, {"id": "Bảo an_5_S00173", "stt": 5, "code": "S00173", "name": "Bùi Doãn Luyến", "dept": "Bảo an", "department": "Utility", "shop": "", "group": "", "note": ""}, {"id": "Bảo an_6_S00178", "stt": 6, "code": "S00178", "name": "Hoàng Đức Quân", "dept": "Bảo an", "department": "Utility", "shop": "", "group": "", "note": ""}, {"id": "Bảo an_7_W00493", "stt": 7, "code": "W00493", "name": "Đoàn Văn Tiến", "dept": "Bảo an", "department": "Utility", "shop": "", "group": "", "note": ""}, {"id": "Bảo an_8_W01244", "stt": 8, "code": "W01244", "name": "Vũ Văn Quý", "dept": "Bảo an", "department": "Utility", "shop": "", "group": "", "note": ""}, {"id": "Bảo an_9_W01246", "stt": 9, "code": "W01246", "name": "Trương Quang Chung", "dept": "Bảo an", "department": "Utility", "shop": "", "group": "", "note": ""}, {"id": "Bảo an_10_W01437", "stt": 10, "code": "W01437", "name": "Đỗ Văn Hoàn", "dept": "Bảo an", "department": "Utility", "shop": "", "group": "", "note": ""}, {"id": "Bảo an_11_W01585", "stt": 11, "code": "W01585", "name": "Nguyễn Thị Mẫn", "dept": "Bảo an", "department": "Utility", "shop": "", "group": "", "note": ""}, {"id": "Bảo an_12_W01690", "stt": 12, "code": "W01690", "name": "Nguyễn Văn Toàn", "dept": "Bảo an", "department": "Utility", "shop": "", "group": "", "note": ""}, {"id": "Bảo an_13_W01748", "stt": 13, "code": "W01748", "name": "Trần Văn Khanh", "dept": "Bảo an", "department": "Utility", "shop": "", "group": "", "note": ""}, {"id": "Bảo an_14_W02237", "stt": 14, "code": "W02237", "name": "Nguyễn Trung Kiên", "dept": "Bảo an", "department": "Utility", "shop": "", "group": "", "note": ""}, {"id": "Bảo an_15_W03538", "stt": 15, "code": "W03538", "name": "Vi Hồng Thái", "dept": "Bảo an", "department": "Utility", "shop": "", "group": "", "note": ""}, {"id": "Bảo an_16_W03634", "stt": 16, "code": "W03634", "name": "Quách Văn Tú", "dept": "Bảo an", "department": "Utility", "shop": "", "group": "", "note": ""}, {"id": "Bảo an_17_W04020", "stt": 17, "code": "W04020", "name": "Nguyễn Danh Hiền", "dept": "Bảo an", "department": "Utility", "shop": "", "group": "", "note": ""}, {"id": "Bảo an_18_W04246", "stt": 18, "code": "W04246", "name": "Trần Thị Kim Oanh", "dept": "Bảo an", "department": "Utility", "shop": "", "group": "", "note": ""}, {"id": "Bảo an_19_W04956", "stt": 19, "code": "W04956", "name": "Trần Văn Bắc", "dept": "Bảo an", "department": "Utility", "shop": "", "group": "", "note": ""}, {"id": "Bảo an_20_W05031", "stt": 20, "code": "W05031", "name": "Vũ Văn Vĩ", "dept": "Bảo an", "department": "Utility", "shop": "", "group": "", "note": ""}, {"id": "Bảo an_21_W05039", "stt": 21, "code": "W05039", "name": "Nguyễn Văn Cảnh", "dept": "Bảo an", "department": "Utility", "shop": "", "group": "", "note": ""}, {"id": "Bảo an_22_W05210", "stt": 22, "code": "W05210", "name": "Lê Văn Mạnh", "dept": "Bảo an", "department": "Utility", "shop": "", "group": "", "note": ""}, {"id": "Bảo an_23_W05437", "stt": 23, "code": "W05437", "name": "Nguyễn Văn Hòa", "dept": "Bảo an", "department": "Utility", "shop": "", "group": "", "note": ""}, {"id": "Bảo an_24_W05609", "stt": 24, "code": "W05609", "name": "Nguyễn Quang Nguyên", "dept": "Bảo an", "department": "Utility", "shop": "", "group": "", "note": ""}, {"id": "Bảo an_25_W05785", "stt": 25, "code": "W05785", "name": "Dương Hồng Khánh", "dept": "Bảo an", "department": "Utility", "shop": "", "group": "", "note": ""}, {"id": "Bảo an_26_W05865", "stt": 26, "code": "W05865", "name": "Nguyễn Thị Bích Lan", "dept": "Bảo an", "department": "Utility", "shop": "", "group": "", "note": ""}, {"id": "Văn Phòng_1_S00012", "stt": 1, "code": "S00012", "name": "Nguyễn Thu Hiền", "dept": "Văn Phòng", "department": "Production Activity", "shop": "", "group": "", "note": ""}, {"id": "Văn Phòng_2_S00101", "stt": 2, "code": "S00101", "name": "Nguyễn Ngọc Tùng", "dept": "Văn Phòng", "department": "Production Activity", "shop": "", "group": "", "note": ""}, {"id": "Văn Phòng_3_W00022", "stt": 3, "code": "W00022", "name": "Nguyễn Văn Luân", "dept": "Văn Phòng", "department": "Production Activity", "shop": "Education", "group": "", "note": ""}, {"id": "Văn Phòng_4_W00036", "stt": 4, "code": "W00036", "name": "Nguyễn Bá Mạnh", "dept": "Văn Phòng", "department": "Production Activity", "shop": "Education", "group": "", "note": ""}, {"id": "Văn Phòng_5_W00083", "stt": 5, "code": "W00083", "name": "Ngô Văn Quỳnh", "dept": "Văn Phòng", "department": "Production Activity", "shop": "Education", "group": "", "note": ""}, {"id": "Văn Phòng_6_W00107", "stt": 6, "code": "W00107", "name": "Hoàng Xuân Toàn", "dept": "Văn Phòng", "department": "Production Activity", "shop": "Education", "group": "", "note": ""}, {"id": "Văn Phòng_7_S00072", "stt": 7, "code": "S00072", "name": "Trần Thị Thuỷ", "dept": "Văn Phòng", "department": "Production Activity", "shop": "Japanese Relation", "group": "", "note": ""}, {"id": "Văn Phòng_8_S00212", "stt": 8, "code": "S00212", "name": "Dương Thị Vui", "dept": "Văn Phòng", "department": "Production Activity", "shop": "Japanese Relation", "group": "", "note": ""}, {"id": "Văn Phòng_9_S00036", "stt": 9, "code": "S00036", "name": "Hoàng Trung Thông", "dept": "Văn Phòng", "department": "Production Activity", "shop": "OSHMS Coordinator", "group": "", "note": ""}, {"id": "Văn Phòng_10_W00060", "stt": 10, "code": "W00060", "name": "Nguyễn Anh Đức", "dept": "Văn Phòng", "department": "Production Activity", "shop": "Production", "group": "", "note": ""}, {"id": "Văn Phòng_11_W00079", "stt": 11, "code": "W00079", "name": "Lưu Xuân Toán", "dept": "Văn Phòng", "department": "Production Activity", "shop": "Production", "group": "", "note": ""}, {"id": "Văn Phòng_12_S00029", "stt": 12, "code": "S00029", "name": "Nguyễn Trung Kiên", "dept": "Văn Phòng", "department": "Production Engineering", "shop": "", "group": "", "note": ""}, {"id": "Văn Phòng_13_S00059", "stt": 13, "code": "S00059", "name": "Nguyễn Xuân Triển", "dept": "Văn Phòng", "department": "Production Engineering", "shop": "Forging/Surface treatment", "group": "", "note": ""}, {"id": "Văn Phòng_14_S00219", "stt": 14, "code": "S00219", "name": "Nguyễn Tiến Chính", "dept": "Văn Phòng", "department": "Production Engineering", "shop": "Forging/Surface treatment", "group": "", "note": ""}, {"id": "Văn Phòng_15_S00228", "stt": 15, "code": "S00228", "name": "Lê Quang Vinh", "dept": "Văn Phòng", "department": "Production Engineering", "shop": "Forging/Surface treatment", "group": "", "note": ""}, {"id": "Văn Phòng_16_S00260", "stt": 16, "code": "S00260", "name": "Bạch Minh Thi", "dept": "Văn Phòng", "department": "Production Engineering", "shop": "Forging/Surface treatment", "group": "", "note": ""}, {"id": "Văn Phòng_17_S00026", "stt": 17, "code": "S00026", "name": "Nguyễn Chí Trung", "dept": "Văn Phòng", "department": "Production Engineering", "shop": "Machining AL", "group": "", "note": ""}, {"id": "Văn Phòng_18_S00060", "stt": 18, "code": "S00060", "name": "Hoàng Tùng", "dept": "Văn Phòng", "department": "Production Engineering", "shop": "Machining AL", "group": "", "note": ""}, {"id": "Văn Phòng_19_S00269", "stt": 19, "code": "S00269", "name": "Phạm Quang Linh", "dept": "Văn Phòng", "department": "Production Engineering", "shop": "Machining AL", "group": "", "note": ""}, {"id": "Văn Phòng_20_S00118", "stt": 20, "code": "S00118", "name": "Tống Ngọc Quyến", "dept": "Văn Phòng", "department": "Production Engineering", "shop": "Machining FE", "group": "", "note": ""}, {"id": "Văn Phòng_21_S00123", "stt": 21, "code": "S00123", "name": "Tạ Quang Được", "dept": "Văn Phòng", "department": "Production Engineering", "shop": "Machining FE", "group": "", "note": ""}, {"id": "Văn Phòng_22_S00145", "stt": 22, "code": "S00145", "name": "Bùi Thanh Liêm", "dept": "Văn Phòng", "department": "Production Engineering", "shop": "Machining FE", "group": "", "note": ""}, {"id": "Văn Phòng_23_S00271", "stt": 23, "code": "S00271", "name": "Phùng Văn Hào", "dept": "Văn Phòng", "department": "Production Engineering", "shop": "Machining FE", "group": "", "note": ""}, {"id": "Văn Phòng_24_S00107", "stt": 24, "code": "S00107", "name": "Nguyễn Viết Văn", "dept": "Văn Phòng", "department": "Production Engineering", "shop": "Casting", "group": "", "note": ""}, {"id": "Văn Phòng_25_S00124", "stt": 25, "code": "S00124", "name": "Nguyễn Trung Kiên", "dept": "Văn Phòng", "department": "Production Engineering", "shop": "Casting", "group": "", "note": ""}, {"id": "Văn Phòng_26_S00152", "stt": 26, "code": "S00152", "name": "Trần Anh Trưởng", "dept": "Văn Phòng", "department": "Production Engineering", "shop": "Casting", "group": "", "note": ""}, {"id": "Văn Phòng_27_S00162", "stt": 27, "code": "S00162", "name": "Nguyễn Văn Toại", "dept": "Văn Phòng", "department": "Production Engineering", "shop": "Casting", "group": "", "note": ""}, {"id": "Văn Phòng_28_S00104", "stt": 28, "code": "S00104", "name": "Dương Văn Cảnh", "dept": "Văn Phòng", "department": "Production Engineering", "shop": "Painting", "group": "", "note": ""}, {"id": "Văn Phòng_29_S00159", "stt": 29, "code": "S00159", "name": "Nguyễn Thị Mỹ Huệ", "dept": "Văn Phòng", "department": "Production Engineering", "shop": "Painting", "group": "", "note": ""}, {"id": "Văn Phòng_30_S00293", "stt": 30, "code": "S00293", "name": "Nguyễn Minh Quân", "dept": "Văn Phòng", "department": "LCA-DX", "shop": "FG/ST", "group": "", "note": ""}, {"id": "Văn Phòng_31_S00296", "stt": 31, "code": "S00296", "name": "Nguyễn Tuấn Vũ", "dept": "Văn Phòng", "department": "LCA-DX", "shop": "Machining", "group": "", "note": ""}, {"id": "Văn Phòng_32_S00167", "stt": 32, "code": "S00167", "name": "Nguyễn Văn Trưởng", "dept": "Văn Phòng", "department": "LCA-DX", "shop": "Coordination", "group": "", "note": ""}, {"id": "Văn Phòng_33_S00259", "stt": 33, "code": "S00259", "name": "Dương Hồng Ngọc", "dept": "Văn Phòng", "department": "LCA-DX", "shop": "Coordination", "group": "", "note": ""}, {"id": "Văn Phòng_34_S00290", "stt": 34, "code": "S00290", "name": "Cấn Khánh Toàn", "dept": "Văn Phòng", "department": "LCA-DX", "shop": "Coordination", "group": "", "note": ""}, {"id": "Văn Phòng_35_S00160", "stt": 35, "code": "S00160", "name": "Lê Duy Thanh", "dept": "Văn Phòng", "department": "Robotic Operations", "shop": "SMT Business", "group": "", "note": ""}, {"id": "Văn Phòng_36_S00194", "stt": 36, "code": "S00194", "name": "Phan Trung Kiên", "dept": "Văn Phòng", "department": "Robotic Operations", "shop": "SMT Business", "group": "", "note": ""}, {"id": "Văn Phòng_37_S00284", "stt": 37, "code": "S00284", "name": "Bùi Quang Anh", "dept": "Văn Phòng", "department": "Robotic Operations", "shop": "FA Business", "group": "", "note": ""}, {"id": "Văn Phòng_38_S00279", "stt": 38, "code": "S00279", "name": "Lê Đoàn Bích Ngọc", "dept": "Văn Phòng", "department": "Robotic Operations", "shop": "Admin & Operation", "group": "", "note": ""}, {"id": "Văn Phòng_39_S00055", "stt": 39, "code": "S00055", "name": "Vũ Thị Kim Thoa", "dept": "Văn Phòng", "department": "Internal Audit", "shop": "", "group": "", "note": ""}, {"id": "Văn Phòng_40_S00256", "stt": 40, "code": "S00256", "name": "Phùng Hải Yến", "dept": "Văn Phòng", "department": "Internal Audit", "shop": "", "group": "", "note": ""}, {"id": "Văn Phòng_41_S00182", "stt": 41, "code": "S00182", "name": "Đặng Hồng Vân", "dept": "Văn Phòng", "department": "General Affairs", "shop": "", "group": "", "note": ""}, {"id": "Văn Phòng_42_W05854", "stt": 42, "code": "W05854", "name": "Trần Thị Thúy Thêm", "dept": "Văn Phòng", "department": "General Affairs", "shop": "", "group": "", "note": ""}, {"id": "Văn Phòng_43_W05855", "stt": 43, "code": "W05855", "name": "Đào Thị Lan Anh", "dept": "Văn Phòng", "department": "General Affairs", "shop": "", "group": "", "note": ""}, {"id": "Văn Phòng_44_W05856", "stt": 44, "code": "W05856", "name": "Đỗ Thị Hiền", "dept": "Văn Phòng", "department": "General Affairs", "shop": "", "group": "", "note": ""}, {"id": "Văn Phòng_45_D00024", "stt": 45, "code": "D00024", "name": "Trần Thị Thùy", "dept": "Văn Phòng", "department": "General Affairs", "shop": "Office", "group": "", "note": ""}, {"id": "Văn Phòng_46_S00166", "stt": 46, "code": "S00166", "name": "Nguyễn Tiến Nam", "dept": "Văn Phòng", "department": "General Affairs", "shop": "Office", "group": "", "note": ""}, {"id": "Văn Phòng_47_S00285", "stt": 47, "code": "S00285", "name": "Lê Kiều Trinh", "dept": "Văn Phòng", "department": "General Affairs", "shop": "Office", "group": "", "note": ""}, {"id": "Văn Phòng_48_S00292", "stt": 48, "code": "S00292", "name": "Phạm Bá Nhật Anh", "dept": "Văn Phòng", "department": "General Affairs", "shop": "Office", "group": "", "note": ""}, {"id": "Văn Phòng_49_S00306", "stt": 49, "code": "S00306", "name": "Lưu Hữu Tuấn", "dept": "Văn Phòng", "department": "General Affairs", "shop": "Office", "group": "", "note": ""}, {"id": "Văn Phòng_50_W00202", "stt": 50, "code": "W00202", "name": "Nguyễn Đức Văn", "dept": "Văn Phòng", "department": "General Affairs", "shop": "Genba", "group": "", "note": ""}, {"id": "Văn Phòng_51_W00907", "stt": 51, "code": "W00907", "name": "Nguyễn Thị Điệp", "dept": "Văn Phòng", "department": "General Affairs", "shop": "Genba", "group": "", "note": ""}, {"id": "Văn Phòng_52_W01175", "stt": 52, "code": "W01175", "name": "Thái Thị Lựu", "dept": "Văn Phòng", "department": "General Affairs", "shop": "Genba", "group": "", "note": ""}, {"id": "Văn Phòng_53_W04000", "stt": 53, "code": "W04000", "name": "Hoàng Lan Hương", "dept": "Văn Phòng", "department": "General Affairs", "shop": "Genba", "group": "", "note": ""}, {"id": "Văn Phòng_54_W04239", "stt": 54, "code": "W04239", "name": "Nguyễn Thị Thu Thủy", "dept": "Văn Phòng", "department": "General Affairs", "shop": "Genba", "group": "", "note": ""}, {"id": "Văn Phòng_55_W04467", "stt": 55, "code": "W04467", "name": "Nguyễn Thị Ngọc", "dept": "Văn Phòng", "department": "General Affairs", "shop": "Genba", "group": "", "note": ""}, {"id": "Văn Phòng_56_W04514", "stt": 56, "code": "W04514", "name": "Lương Thị Hoài", "dept": "Văn Phòng", "department": "General Affairs", "shop": "Genba", "group": "", "note": ""}, {"id": "Văn Phòng_57_W05720", "stt": 57, "code": "W05720", "name": "Đồng Văn Đông", "dept": "Văn Phòng", "department": "General Affairs", "shop": "Genba", "group": "", "note": ""}, {"id": "Văn Phòng_58_W05833", "stt": 58, "code": "W05833", "name": "Nguyễn Thị Hương", "dept": "Văn Phòng", "department": "General Affairs", "shop": "Genba", "group": "", "note": ""}, {"id": "Văn Phòng_59_W05860", "stt": 59, "code": "W05860", "name": "Phạm Thị Sửu", "dept": "Văn Phòng", "department": "Parts control", "shop": "", "group": "", "note": ""}, {"id": "Văn Phòng_60_W05861", "stt": 60, "code": "W05861", "name": "Nguyễn Thị Đức", "dept": "Văn Phòng", "department": "Parts control", "shop": "", "group": "", "note": ""}, {"id": "Văn Phòng_61_W05862", "stt": 61, "code": "W05862", "name": "Ngô Thị Thu Huyền", "dept": "Văn Phòng", "department": "Parts control", "shop": "", "group": "", "note": ""}, {"id": "Văn Phòng_62_W05863", "stt": 62, "code": "W05863", "name": "Đào Thị Nhiễu", "dept": "Văn Phòng", "department": "Parts control", "shop": "", "group": "", "note": ""}, {"id": "Văn Phòng_63_W00218", "stt": 63, "code": "W00218", "name": "Nguyễn Văn Tiến", "dept": "Văn Phòng", "department": "Parts control", "shop": "Delivery", "group": "", "note": ""}, {"id": "Văn Phòng_64_W00942", "stt": 64, "code": "W00942", "name": "Nguyễn Thị Khuyên", "dept": "Văn Phòng", "department": "Parts control", "shop": "Delivery", "group": "", "note": ""}, {"id": "Văn Phòng_65_W01029", "stt": 65, "code": "W01029", "name": "Hoàng Thị Hoa", "dept": "Văn Phòng", "department": "Parts control", "shop": "Delivery", "group": "", "note": ""}, {"id": "Văn Phòng_66_W02177", "stt": 66, "code": "W02177", "name": "Nguyễn Thị Điểm", "dept": "Văn Phòng", "department": "Parts control", "shop": "Delivery", "group": "", "note": ""}, {"id": "Văn Phòng_67_W03088", "stt": 67, "code": "W03088", "name": "Nguyễn Thị Hồng Dương", "dept": "Văn Phòng", "department": "Parts control", "shop": "Delivery", "group": "", "note": ""}, {"id": "Văn Phòng_68_W03195", "stt": 68, "code": "W03195", "name": "Sái Công Hùng", "dept": "Văn Phòng", "department": "Parts control", "shop": "Delivery", "group": "", "note": ""}, {"id": "Văn Phòng_69_W03715", "stt": 69, "code": "W03715", "name": "Hà Thị Hồng", "dept": "Văn Phòng", "department": "Parts control", "shop": "Delivery", "group": "", "note": ""}, {"id": "Văn Phòng_70_W04478", "stt": 70, "code": "W04478", "name": "Nguyễn Thị Thanh Hường", "dept": "Văn Phòng", "department": "Parts control", "shop": "Delivery", "group": "", "note": ""}, {"id": "Văn Phòng_71_W05513", "stt": 71, "code": "W05513", "name": "Nguyễn Thu Hà", "dept": "Văn Phòng", "department": "Parts control", "shop": "Delivery", "group": "", "note": ""}, {"id": "Văn Phòng_72_S00122", "stt": 72, "code": "S00122", "name": "Nguyễn Phương Thảo", "dept": "Văn Phòng", "department": "Parts control", "shop": "Warehousing", "group": "", "note": ""}, {"id": "Văn Phòng_73_W00042", "stt": 73, "code": "W00042", "name": "Trần Thị Xiêm", "dept": "Văn Phòng", "department": "Parts control", "shop": "Warehousing", "group": "", "note": ""}, {"id": "Văn Phòng_74_W00518", "stt": 74, "code": "W00518", "name": "Nguyễn Văn Cần", "dept": "Văn Phòng", "department": "Parts control", "shop": "Warehousing", "group": "", "note": ""}, {"id": "Văn Phòng_75_W01077", "stt": 75, "code": "W01077", "name": "Nguyễn Văn Tuấn", "dept": "Văn Phòng", "department": "Parts control", "shop": "Warehousing", "group": "", "note": ""}, {"id": "Văn Phòng_76_W01178", "stt": 76, "code": "W01178", "name": "Phạm Thị Hiếu", "dept": "Văn Phòng", "department": "Parts control", "shop": "Warehousing", "group": "", "note": ""}, {"id": "Văn Phòng_77_W03180", "stt": 77, "code": "W03180", "name": "Nguyễn Đức Toàn", "dept": "Văn Phòng", "department": "Parts control", "shop": "Warehousing", "group": "", "note": ""}, {"id": "Văn Phòng_78_W04584", "stt": 78, "code": "W04584", "name": "Đoàn Thị Hằng", "dept": "Văn Phòng", "department": "Parts control", "shop": "Warehousing", "group": "", "note": ""}, {"id": "Văn Phòng_79_S00054", "stt": 79, "code": "S00054", "name": "Lại Thị Hải Yến", "dept": "Văn Phòng", "department": "Parts control", "shop": "Receiving", "group": "", "note": ""}, {"id": "Văn Phòng_80_W00307", "stt": 80, "code": "W00307", "name": "Đặng Kim Thêu", "dept": "Văn Phòng", "department": "Parts control", "shop": "Receiving", "group": "", "note": ""}, {"id": "Văn Phòng_81_W01046", "stt": 81, "code": "W01046", "name": "Hoàng Thị Nhàn", "dept": "Văn Phòng", "department": "Parts control", "shop": "Receiving", "group": "", "note": ""}, {"id": "Văn Phòng_82_W01868", "stt": 82, "code": "W01868", "name": "Đỗ Thị Thiện", "dept": "Văn Phòng", "department": "Parts control", "shop": "Receiving", "group": "", "note": ""}, {"id": "Văn Phòng_83_S00265", "stt": 83, "code": "S00265", "name": "Nguyễn Thị Vân", "dept": "Văn Phòng", "department": "Accounting", "shop": "", "group": "", "note": ""}, {"id": "Văn Phòng_84_S00310", "stt": 84, "code": "S00310", "name": "Đào Trà My", "dept": "Văn Phòng", "department": "Accounting", "shop": "", "group": "", "note": ""}, {"id": "Văn Phòng_85_S00149", "stt": 85, "code": "S00149", "name": "Phạm Ngọc Mai", "dept": "Văn Phòng", "department": "Accounting", "shop": "Business Planning", "group": "", "note": ""}, {"id": "Văn Phòng_86_S00136", "stt": 86, "code": "S00136", "name": "Nguyễn Thị Ngoan", "dept": "Văn Phòng", "department": "Accounting", "shop": "Cost planning Inventory", "group": "", "note": ""}, {"id": "Văn Phòng_87_S00251", "stt": 87, "code": "S00251", "name": "Phạm Thị Hường", "dept": "Văn Phòng", "department": "Accounting", "shop": "AR-Reporting", "group": "", "note": ""}, {"id": "Văn Phòng_88_S00277", "stt": 88, "code": "S00277", "name": "Đỗ Thanh Xuân", "dept": "Văn Phòng", "department": "Accounting", "shop": "AP-Fix Asset", "group": "", "note": ""}, {"id": "Văn Phòng_89_S00298", "stt": 89, "code": "S00298", "name": "Hà Khánh Linh", "dept": "Văn Phòng", "department": "Accounting", "shop": "AP-Fix Asset", "group": "", "note": ""}, {"id": "Văn Phòng_90_S00132", "stt": 90, "code": "S00132", "name": "Hoàng Thu Lan", "dept": "Văn Phòng", "department": "Accounting", "shop": "Tax Compliance", "group": "", "note": ""}, {"id": "Văn Phòng_91_S00250", "stt": 91, "code": "S00250", "name": "Nguyễn Thị Thu Hà", "dept": "Văn Phòng", "department": "Accounting", "shop": "Bank-Treasury", "group": "", "note": ""}, {"id": "Văn Phòng_92_S00297", "stt": 92, "code": "S00297", "name": "Trần Quỳnh Trang", "dept": "Văn Phòng", "department": "Accounting", "shop": "Bank-Treasury", "group": "", "note": ""}, {"id": "Văn Phòng_93_S00007", "stt": 93, "code": "S00007", "name": "Đỗ Văn Hưng", "dept": "Văn Phòng", "department": "Quality Assurance", "shop": "", "group": "", "note": ""}, {"id": "Văn Phòng_94_S00006", "stt": 94, "code": "S00006", "name": "Lý Nam Giang", "dept": "Văn Phòng", "department": "Quality Assurance", "shop": "New model", "group": "", "note": ""}, {"id": "Văn Phòng_95_S00155", "stt": 95, "code": "S00155", "name": "Lê Huy Sang", "dept": "Văn Phòng", "department": "Quality Assurance", "shop": "QA", "group": "", "note": ""}, {"id": "Văn Phòng_96_S00019", "stt": 96, "code": "S00019", "name": "Hoàng Thị Thu Minh", "dept": "Văn Phòng", "department": "Human Resources", "shop": "", "group": "", "note": ""}, {"id": "Văn Phòng_97_W05858", "stt": 97, "code": "W05858", "name": "Nguyễn Thị Huệ", "dept": "Văn Phòng", "department": "Human Resources", "shop": "", "group": "", "note": ""}, {"id": "Văn Phòng_98_S00304", "stt": 98, "code": "S00304", "name": "Phạm Thị Hương", "dept": "Văn Phòng", "department": "Human Resources", "shop": "Legal", "group": "", "note": ""}, {"id": "Văn Phòng_99_S00075", "stt": 99, "code": "S00075", "name": "Đặng Mai Hoa", "dept": "Văn Phòng", "department": "Human Resources", "shop": "HR", "group": "", "note": ""}, {"id": "Văn Phòng_100_S00196", "stt": 100, "code": "S00196", "name": "Nguyễn Thị Dịu", "dept": "Văn Phòng", "department": "Human Resources", "shop": "HR", "group": "", "note": ""}, {"id": "Văn Phòng_101_S00240", "stt": 101, "code": "S00240", "name": "Vũ Xuân Bách", "dept": "Văn Phòng", "department": "Human Resources", "shop": "HR", "group": "", "note": ""}, {"id": "Văn Phòng_102_S00244", "stt": 102, "code": "S00244", "name": "Lê Thị Thúy", "dept": "Văn Phòng", "department": "Human Resources", "shop": "HR", "group": "", "note": ""}, {"id": "Văn Phòng_103_S00303", "stt": 103, "code": "S00303", "name": "Nguyễn Thị Loan", "dept": "Văn Phòng", "department": "Human Resources", "shop": "HR", "group": "", "note": ""}, {"id": "Văn Phòng_104_W02425", "stt": 104, "code": "W02425", "name": "Nguyễn Thị Quế", "dept": "Văn Phòng", "department": "Human Resources", "shop": "HR", "group": "", "note": ""}, {"id": "Văn Phòng_105_W05449", "stt": 105, "code": "W05449", "name": "Nguyễn Ngọc Long", "dept": "Văn Phòng", "department": "Human Resources", "shop": "IT", "group": "", "note": ""}, {"id": "Văn Phòng_106_S00016", "stt": 106, "code": "S00016", "name": "Nguyễn Ngọc Linh", "dept": "Văn Phòng", "department": "Procurement", "shop": "", "group": "", "note": ""}, {"id": "Văn Phòng_107_W05859", "stt": 107, "code": "W05859", "name": "Nguyễn Thị An", "dept": "Văn Phòng", "department": "Procurement", "shop": "", "group": "", "note": ""}, {"id": "Văn Phòng_108_S00227", "stt": 108, "code": "S00227", "name": "Phạm Thị Hồng", "dept": "Văn Phòng", "department": "Procurement", "shop": "PO/Receiving", "group": "", "note": ""}, {"id": "Văn Phòng_109_W01550", "stt": 109, "code": "W01550", "name": "Nguyễn Thị Thư", "dept": "Văn Phòng", "department": "Procurement", "shop": "PO/Receiving", "group": "", "note": ""}, {"id": "Văn Phòng_110_W02651", "stt": 110, "code": "W02651", "name": "Vũ Thị Thu Hà", "dept": "Văn Phòng", "department": "Procurement", "shop": "PO/Receiving", "group": "", "note": ""}, {"id": "Văn Phòng_111_S00275", "stt": 111, "code": "S00275", "name": "Nguyễn Tuấn Anh", "dept": "Văn Phòng", "department": "Procurement", "shop": "DX", "group": "", "note": ""}, {"id": "Văn Phòng_112_S00198", "stt": 112, "code": "S00198", "name": "Nguyễn Lan Anh", "dept": "Văn Phòng", "department": "Procurement", "shop": "Buyer", "group": "", "note": ""}, {"id": "Văn Phòng_113_S00245", "stt": 113, "code": "S00245", "name": "Bùi Thị Vân", "dept": "Văn Phòng", "department": "Procurement", "shop": "Buyer", "group": "", "note": ""}, {"id": "Văn Phòng_114_S00274", "stt": 114, "code": "S00274", "name": "Đặng Vũ Thương Huyền", "dept": "Văn Phòng", "department": "Procurement", "shop": "Buyer", "group": "", "note": ""}, {"id": "Văn Phòng_115_S00291", "stt": 115, "code": "S00291", "name": "Nguyễn Thị Hồng Tươi", "dept": "Văn Phòng", "department": "Procurement", "shop": "Buyer", "group": "", "note": ""}, {"id": "Văn Phòng_116_S00299", "stt": 116, "code": "S00299", "name": "Ngô Khánh Linh", "dept": "Văn Phòng", "department": "Procurement", "shop": "Buyer", "group": "", "note": ""}, {"id": "Văn Phòng_117_S00302", "stt": 117, "code": "S00302", "name": "Vương Thị Nguyệt", "dept": "Văn Phòng", "department": "Procurement", "shop": "Buyer", "group": "", "note": ""}, {"id": "Văn Phòng_118_W05230", "stt": 118, "code": "W05230", "name": "Nguyễn Thị Thuân", "dept": "Văn Phòng", "department": "Procurement", "shop": "Buyer", "group": "", "note": ""}, {"id": "Văn Phòng_119_S00264", "stt": 119, "code": "S00264", "name": "Trần Hiển", "dept": "Văn Phòng", "department": "Production Planning", "shop": "", "group": "", "note": ""}, {"id": "Văn Phòng_120_W05876", "stt": 120, "code": "W05876", "name": "Hoàng Thị Minh", "dept": "Văn Phòng", "department": "Production Planning", "shop": "", "group": "", "note": ""}, {"id": "Văn Phòng_121_S00241", "stt": 121, "code": "S00241", "name": "Cao Diễm My", "dept": "Văn Phòng", "department": "Production Planning", "shop": "Logistics", "group": "", "note": ""}, {"id": "Văn Phòng_122_S00282", "stt": 122, "code": "S00282", "name": "Đinh Thế Hoàng", "dept": "Văn Phòng", "department": "Production Planning", "shop": "Logistics", "group": "", "note": ""}, {"id": "Văn Phòng_123_W00053", "stt": 123, "code": "W00053", "name": "Nguyễn Thị Thu Thuỷ", "dept": "Văn Phòng", "department": "Production Planning", "shop": "Logistics", "group": "", "note": ""}, {"id": "Văn Phòng_124_W00066", "stt": 124, "code": "W00066", "name": "Vũ Ngọc Mỹ", "dept": "Văn Phòng", "department": "Production Planning", "shop": "Logistics", "group": "", "note": ""}, {"id": "Văn Phòng_125_W00072", "stt": 125, "code": "W00072", "name": "Đàm Đình Vũ", "dept": "Văn Phòng", "department": "Production Planning", "shop": "Logistics", "group": "", "note": ""}, {"id": "Văn Phòng_126_W00088", "stt": 126, "code": "W00088", "name": "Nguyễn Viết Thắng", "dept": "Văn Phòng", "department": "Production Planning", "shop": "Logistics", "group": "", "note": ""}, {"id": "Văn Phòng_127_W00238", "stt": 127, "code": "W00238", "name": "Nguyễn Thị Hưng", "dept": "Văn Phòng", "department": "Production Planning", "shop": "Logistics", "group": "", "note": ""}, {"id": "Văn Phòng_128_W00309", "stt": 128, "code": "W00309", "name": "Ngô Thị Đào", "dept": "Văn Phòng", "department": "Production Planning", "shop": "Logistics", "group": "", "note": ""}, {"id": "Văn Phòng_129_W00314", "stt": 129, "code": "W00314", "name": "Trần Thị Xuân", "dept": "Văn Phòng", "department": "Production Planning", "shop": "Logistics", "group": "", "note": ""}, {"id": "Văn Phòng_130_W00468", "stt": 130, "code": "W00468", "name": "Lê Thị Tâm", "dept": "Văn Phòng", "department": "Production Planning", "shop": "Logistics", "group": "", "note": ""}, {"id": "Văn Phòng_131_W00476", "stt": 131, "code": "W00476", "name": "Nguyễn Thị Lý", "dept": "Văn Phòng", "department": "Production Planning", "shop": "Logistics", "group": "", "note": ""}, {"id": "Văn Phòng_132_W00548", "stt": 132, "code": "W00548", "name": "Đặng Thị Nhàng", "dept": "Văn Phòng", "department": "Production Planning", "shop": "Logistics", "group": "", "note": ""}, {"id": "Văn Phòng_133_W00947", "stt": 133, "code": "W00947", "name": "Kiều Thị Loan", "dept": "Văn Phòng", "department": "Production Planning", "shop": "Logistics", "group": "", "note": ""}, {"id": "Văn Phòng_134_W01041", "stt": 134, "code": "W01041", "name": "Nguyễn Thị Mến", "dept": "Văn Phòng", "department": "Production Planning", "shop": "Logistics", "group": "", "note": ""}, {"id": "Văn Phòng_135_W01091", "stt": 135, "code": "W01091", "name": "Đỗ Thị Hạnh", "dept": "Văn Phòng", "department": "Production Planning", "shop": "Logistics", "group": "", "note": ""}, {"id": "Văn Phòng_136_W01108", "stt": 136, "code": "W01108", "name": "Trương Minh Hoàn", "dept": "Văn Phòng", "department": "Production Planning", "shop": "Logistics", "group": "", "note": ""}, {"id": "Văn Phòng_137_W01134", "stt": 137, "code": "W01134", "name": "Lê Văn Mạnh", "dept": "Văn Phòng", "department": "Production Planning", "shop": "Logistics", "group": "", "note": ""}, {"id": "Văn Phòng_138_W01152", "stt": 138, "code": "W01152", "name": "Lê Thị Oanh", "dept": "Văn Phòng", "department": "Production Planning", "shop": "Logistics", "group": "", "note": ""}, {"id": "Văn Phòng_139_W01177", "stt": 139, "code": "W01177", "name": "Nguyễn Thị Bích Huyền", "dept": "Văn Phòng", "department": "Production Planning", "shop": "Logistics", "group": "", "note": ""}, {"id": "Văn Phòng_140_W01340", "stt": 140, "code": "W01340", "name": "Phạm Thị Thanh Bình", "dept": "Văn Phòng", "department": "Production Planning", "shop": "Logistics", "group": "", "note": ""}, {"id": "Văn Phòng_141_W01394", "stt": 141, "code": "W01394", "name": "Lưu Thị Lịch", "dept": "Văn Phòng", "department": "Production Planning", "shop": "Logistics", "group": "", "note": ""}, {"id": "Văn Phòng_142_W01484", "stt": 142, "code": "W01484", "name": "Đỗ Thị Nguyệt", "dept": "Văn Phòng", "department": "Production Planning", "shop": "Logistics", "group": "", "note": ""}, {"id": "Văn Phòng_143_W01486", "stt": 143, "code": "W01486", "name": "Nguyễn Thị Thu Hương", "dept": "Văn Phòng", "department": "Production Planning", "shop": "Logistics", "group": "", "note": ""}, {"id": "Văn Phòng_144_W01496", "stt": 144, "code": "W01496", "name": "Nguyễn Huy Cường", "dept": "Văn Phòng", "department": "Production Planning", "shop": "Logistics", "group": "", "note": ""}, {"id": "Văn Phòng_145_W01563", "stt": 145, "code": "W01563", "name": "Nguyễn Thị Lại", "dept": "Văn Phòng", "department": "Production Planning", "shop": "Logistics", "group": "", "note": ""}, {"id": "Văn Phòng_146_W01821", "stt": 146, "code": "W01821", "name": "Trần Thị Lan Anh", "dept": "Văn Phòng", "department": "Production Planning", "shop": "Logistics", "group": "", "note": ""}, {"id": "Văn Phòng_147_W02087", "stt": 147, "code": "W02087", "name": "Phạm Văn Đông", "dept": "Văn Phòng", "department": "Production Planning", "shop": "Logistics", "group": "", "note": ""}, {"id": "Văn Phòng_148_W02352", "stt": 148, "code": "W02352", "name": "Trương Thị Giang", "dept": "Văn Phòng", "department": "Production Planning", "shop": "Logistics", "group": "", "note": ""}, {"id": "Văn Phòng_149_W02722", "stt": 149, "code": "W02722", "name": "Nguyễn Như Ngọc", "dept": "Văn Phòng", "department": "Production Planning", "shop": "Logistics", "group": "", "note": ""}, {"id": "Văn Phòng_150_W03028", "stt": 150, "code": "W03028", "name": "Đỗ Thị Xuyên", "dept": "Văn Phòng", "department": "Production Planning", "shop": "Logistics", "group": "", "note": ""}, {"id": "Văn Phòng_151_W03268", "stt": 151, "code": "W03268", "name": "Lê Thị Chanh", "dept": "Văn Phòng", "department": "Production Planning", "shop": "Logistics", "group": "", "note": ""}, {"id": "Văn Phòng_152_W03424", "stt": 152, "code": "W03424", "name": "Phạm Văn Thắng", "dept": "Văn Phòng", "department": "Production Planning", "shop": "Logistics", "group": "", "note": ""}, {"id": "Văn Phòng_153_W03511", "stt": 153, "code": "W03511", "name": "Ngô Thị Hiền", "dept": "Văn Phòng", "department": "Production Planning", "shop": "Logistics", "group": "", "note": ""}, {"id": "Văn Phòng_154_W03647", "stt": 154, "code": "W03647", "name": "Đỗ Thị Ánh", "dept": "Văn Phòng", "department": "Production Planning", "shop": "Logistics", "group": "", "note": ""}, {"id": "Văn Phòng_155_W03695", "stt": 155, "code": "W03695", "name": "Lê Văn Nam", "dept": "Văn Phòng", "department": "Production Planning", "shop": "Logistics", "group": "", "note": ""}, {"id": "Văn Phòng_156_W04580", "stt": 156, "code": "W04580", "name": "Dương Thị Súy", "dept": "Văn Phòng", "department": "Production Planning", "shop": "Logistics", "group": "", "note": ""}, {"id": "Văn Phòng_157_W04962", "stt": 157, "code": "W04962", "name": "Phạm Thị Chung", "dept": "Văn Phòng", "department": "Production Planning", "shop": "Logistics", "group": "", "note": ""}, {"id": "Văn Phòng_158_W04996", "stt": 158, "code": "W04996", "name": "Nguyễn Thị Tuyết Mai", "dept": "Văn Phòng", "department": "Production Planning", "shop": "Logistics", "group": "", "note": ""}, {"id": "Văn Phòng_159_W05042", "stt": 159, "code": "W05042", "name": "Trịnh Minh Phương", "dept": "Văn Phòng", "department": "Production Planning", "shop": "Logistics", "group": "", "note": ""}, {"id": "Văn Phòng_160_W05151", "stt": 160, "code": "W05151", "name": "Nguyễn Công Thành", "dept": "Văn Phòng", "department": "Production Planning", "shop": "Logistics", "group": "", "note": ""}, {"id": "Văn Phòng_161_W05234", "stt": 161, "code": "W05234", "name": "Nguyễn Duy Toàn", "dept": "Văn Phòng", "department": "Production Planning", "shop": "Logistics", "group": "", "note": ""}, {"id": "Văn Phòng_162_W05372", "stt": 162, "code": "W05372", "name": "Nguyễn Xuân Trường", "dept": "Văn Phòng", "department": "Production Planning", "shop": "Logistics", "group": "", "note": ""}, {"id": "Văn Phòng_163_W05373", "stt": 163, "code": "W05373", "name": "Nguyễn Văn Truyên", "dept": "Văn Phòng", "department": "Production Planning", "shop": "Logistics", "group": "", "note": ""}, {"id": "Văn Phòng_164_W05496", "stt": 164, "code": "W05496", "name": "Đỗ Quang Huy", "dept": "Văn Phòng", "department": "Production Planning", "shop": "Logistics", "group": "", "note": ""}, {"id": "Văn Phòng_165_W05556", "stt": 165, "code": "W05556", "name": "Nguyễn Ngọc Phương", "dept": "Văn Phòng", "department": "Production Planning", "shop": "Logistics", "group": "", "note": ""}, {"id": "Văn Phòng_166_W05658", "stt": 166, "code": "W05658", "name": "Trần Văn Hưng", "dept": "Văn Phòng", "department": "Production Planning", "shop": "Logistics", "group": "", "note": ""}, {"id": "Văn Phòng_167_W05682", "stt": 167, "code": "W05682", "name": "Phạm Thị Hồng", "dept": "Văn Phòng", "department": "Production Planning", "shop": "Logistics", "group": "", "note": ""}, {"id": "Văn Phòng_168_W05749", "stt": 168, "code": "W05749", "name": "Tạ Văn Chính", "dept": "Văn Phòng", "department": "Production Planning", "shop": "Logistics", "group": "", "note": ""}, {"id": "Văn Phòng_169_W05779", "stt": 169, "code": "W05779", "name": "Hoàng Ngọc Định", "dept": "Văn Phòng", "department": "Production Planning", "shop": "Logistics", "group": "", "note": ""}, {"id": "Văn Phòng_170_W05857", "stt": 170, "code": "W05857", "name": "Nguyễn Thị Hương", "dept": "Văn Phòng", "department": "Production Planning", "shop": "Logistics", "group": "", "note": ""}, {"id": "Văn Phòng_171_S00051", "stt": 171, "code": "S00051", "name": "Dương Bích Ngà", "dept": "Văn Phòng", "department": "Production Planning", "shop": "Production Information", "group": "", "note": ""}, {"id": "Văn Phòng_172_S00179", "stt": 172, "code": "S00179", "name": "Nguyễn Thị Ngọc Lan", "dept": "Văn Phòng", "department": "Production Planning", "shop": "Production Planning and Control", "group": "", "note": ""}, {"id": "Văn Phòng_173_W02432", "stt": 173, "code": "W02432", "name": "Nguyễn Thị Thùy", "dept": "Văn Phòng", "department": "Production Planning", "shop": "Production Planning and Control", "group": "", "note": ""}, {"id": "Văn Phòng_174_W05128", "stt": 174, "code": "W05128", "name": "Nguyễn Thị Thanh Mai", "dept": "Văn Phòng", "department": "Production Planning", "shop": "Production Planning and Control", "group": "", "note": ""}, {"id": "Văn Phòng_175_S00283", "stt": 175, "code": "S00283", "name": "Bùi Đăng Hồng", "dept": "Văn Phòng", "department": "Production Planning", "shop": "Cost and Quotation control", "group": "", "note": ""}, {"id": "Văn Phòng_176_S00287", "stt": 176, "code": "S00287", "name": "Đặng Thị Hiền", "dept": "Văn Phòng", "department": "Production Planning", "shop": "Cost and Quotation control", "group": "", "note": ""}];

const DEFAULT_PLANS = [
  { id: 'p1', title: 'Khám sức khỏe định kỳ & Tầm soát bệnh nghề nghiệp cho Đoàn viên YPMV', date: '2026-11-22', category: 'Chăm lo phúc lợi', location: 'Khu vực Y tế & Nhà đa năng Công ty YPMV', participants: 'Toàn thể Công đoàn viên 7 bộ phận (chia theo ca)', status: 'Sắp diễn ra', desc: 'Phối hợp cùng bệnh viện tuyến trung ương tổ chức khám tổng quát, siêu âm, xét nghiệm máu và kiểm tra thính lực/hô hấp cho đoàn viên khối sản xuất Đúc, Gia công cơ khí và Lắp ráp.' },
  { id: 'p2', title: 'Hội nghị Đối thoại Định kỳ giữa Ban Giám đốc và Người lao động Quý IV', date: '2026-12-05', category: 'Đối thoại & Bảo vệ NLĐ', location: 'Phòng Họp Lớn Tầng 2 - Nhà Điều Hành YPMV', participants: 'BCH Công đoàn, Tổ trưởng CĐ và đại diện các bộ phận', status: 'Đang lấy ý kiến', desc: 'Tổng hợp ý kiến đóng góp từ các hòm thư Công đoàn về chế độ ca đêm, chất lượng bữa ăn ca, trang bị bảo hộ lao động mùa đông và thưởng Tết Nguyên Đán.' },
  { id: 'p3', title: 'Chương trình "Tết Sum Vầy - Chuyến Xe Công Đoàn YPMV Đưa Đoàn Viên Về Quê"', date: '2027-01-18', category: 'Chăm lo phúc lợi', location: 'Sân chính Công ty TNHH SX Phụ Tùng Yamaha Motor VN', participants: 'Toàn thể Công đoàn viên & Gia đình', status: 'Đang triển khai', desc: 'Trao túi quà Tết Công đoàn cho 100% đoàn viên, bốc thăm trúng thưởng xe máy Yamaha, hỗ trợ vé xe giường nằm miễn phí cho đoàn viên quê xa.' },
  { id: 'p4', title: 'Giải Bóng đá Nam - Nữ & Kéo co Truyền thống Yamaha Parts Cup', date: '2027-03-14', category: 'Văn hóa - Thể thao', location: 'Khu liên hợp thể thao KCN', participants: 'Đội tuyển 7 bộ phận Đúc, Gia công, Lắp ráp, QC, Bảo trì, Kho, Văn phòng', status: 'Đang triển khai', desc: 'Hoạt động thể thao thường niên chào mừng Tháng Công nhân, nâng cao sức khỏe và tinh thần đoàn kết giữa các phân xưởng sản xuất phụ tùng Yamaha.' },
  { id: 'p5', title: 'Lễ Tôn vinh "Bàn Tay Vàng & Sáng Kiến Kaizen Xuất Sắc YPMV"', date: '2027-05-08', category: 'Thi đua sản xuất', location: 'Hội trường Công ty YPMV', participants: 'Các cá nhân và tổ sản xuất có cải tiến kỹ thuật tiêu biểu', status: 'Sắp diễn ra', desc: 'Khen thưởng các đoàn viên có sáng kiến giảm tỷ lệ hàng lỗi (NG), tiết kiệm năng lượng tại xưởng Đúc và rút ngắn thời gian gá đặt tại xưởng Gia công CNC.' },
];

const DEFAULT_POLICIES = [
  { id: 'pol1', group: 'Hiếu - Hỷ - Thăm hỏi', title: 'Mừng kết hôn Đoàn viên Công đoàn', amount: '1.000.000 VNĐ / đoàn viên', desc: 'Áp dụng cho đoàn viên chính thức kết hôn (nộp bản sao Giấy đăng ký kết hôn cho Tổ trưởng Công đoàn bộ phận trong vòng 30 ngày).' },
  { id: 'pol2', group: 'Nữ công & Con đoàn viên', title: 'Chúc mừng Đoàn viên sinh con (Nam & Nữ đoàn viên)', amount: '1.000.000 VNĐ / bé', desc: 'Áp dụng cho cả đoàn viên nữ sinh con hoặc đoàn viên nam có vợ sinh con. Ngoài ra nữ đoàn viên mang thai từ tháng thứ 7 được bố trí làm ca hành chính và suất ăn bổ sung.' },
  { id: 'pol3', group: 'Hiếu - Hỷ - Thăm hỏi', title: 'Thăm hỏi ốm đau nằm viện & Phẫu thuật', amount: '500.000 - 2.000.000 VNĐ', desc: 'Đoàn viên điều trị nội trú tại bệnh viện từ 3 ngày trở lên hoặc phẫu thuật được BCH Công đoàn thăm hỏi trực tiếp và hỗ trợ kinh phí.' },
  { id: 'pol4', group: 'Hiếu - Hỷ - Thăm hỏi', title: 'Chế độ Hiếu sự (Tứ thân phụ mẫu, vợ/chồng, con)', amount: '2.000.000 VNĐ + Vòng hoa viếng', desc: 'Công đoàn cơ sở phối hợp cùng bộ phận tổ chức đoàn thăm viếng, chia buồn và hỗ trợ kịp thời cho gia đình đoàn viên.' },
  { id: 'pol5', group: 'Phúc lợi Lễ - Tết', title: 'Quà tặng Sinh nhật, Tết Nguyên Đán, Trung Thu, 8/3 & 20/10', amount: '300.000 - 1.200.000 VNĐ / dịp', desc: 'Mừng sinh nhật đoàn viên hàng tháng, tặng giỏ quà Tết Âm lịch, bánh Trung thu, quà Quốc tế Phụ nữ 8/3, Phụ nữ Việt Nam 20/10 và Quốc tế Thiếu nhi 1/6.' },
  { id: 'pol6', group: 'Nữ công & Con đoàn viên', title: 'Khuyến học "Con Công nhân viên YPMV Học giỏi - Vượt khó"', amount: '500.000 - 1.500.000 VNĐ / cháu', desc: 'Khen thưởng các cháu là con đoàn viên đạt danh hiệu Học sinh Giỏi các cấp, đạt giải thi học sinh giỏi Tỉnh/Thành phố, Quốc gia hoặc đỗ Đại học.' },
  { id: 'pol7', group: 'Bảo hộ & Điều kiện làm việc', title: 'Bữa cơm Công đoàn & Phụ cấp giải nhiệt mùa hè tại Xưởng', amount: 'Suất ăn đặc biệt + Nước điện giải/Sữa chua hàng ngày', desc: 'Tổ chức "Bữa cơm Công đoàn" định kỳ nâng cao khẩu phần dinh dưỡng và cấp phát nước chanh muối, sữa chua mát cho công nhân xưởng Đúc, Gia công trong các tháng nắng nóng.' },
  { id: 'pol8', group: 'Hiếu - Hỷ - Thăm hỏi', title: 'Quỹ Tương trợ Đoàn viên Khó khăn Đột xuất & Mái ấm Công đoàn', amount: '3.000.000 - 15.000.000 VNĐ', desc: 'Hỗ trợ đoàn viên gặp thiên tai, hỏa hoạn, bệnh hiểm nghèo hoặc hoàn cảnh gia đình đặc biệt khó khăn theo đề xuất của Tổ Công đoàn bộ phận.' },
];

const DEFAULT_ACTIVITIES = [
  { id: 'act1', title: 'Bữa Cơm Công Đoàn YPMV - Ấm Áp Tình Đồng Nghiệp Giữa Các Ca Sản Xuất', date: '2026-10-20', tag: 'Chăm lo Đời sống', highlight: '1.450 suất ăn đặc biệt trị giá 65.000đ/suất', summary: 'Ban Chấp hành Công đoàn phối hợp cùng Ban Giám đốc tổ chức Bữa cơm Công đoàn cho toàn thể công nhân viên cả 3 ca với thực đơn bổ dưỡng, trái cây tráng miệng và trao quà mừng ngày Phụ nữ Việt Nam 20/10.', gradient: 'linear-gradient(135deg, #d90429, #9b001a)' },
  { id: 'act2', title: 'Sôi Nổi Giải Bóng Đá Nam - Nữ Công Đoàn Phụ Tùng Yamaha Motor VN', date: '2026-09-15', tag: 'Văn nghệ - Thể thao', highlight: '14 đội bóng từ 7 Bộ phận • Hơn 600 cổ động viên', summary: 'Phân xưởng Gia công cơ khí xuất sắc giành Cúp Vô địch bóng đá nam, trong khi liên quân QC - Lắp ráp đăng quang nội dung bóng đá nữ sau loạt sút luân lưu kịch tính.', gradient: 'linear-gradient(135deg, #1d4ed8, #1e3a8a)' },
  { id: 'act3', title: 'Ngày Hội Gia Đình & Vui Tết Trung Thu Cho Con Em Công Nhân Viên YPMV', date: '2026-09-25', tag: 'Chăm lo Đời sống', highlight: 'Trao 1.800 phần quà Trung thu & 240 suất học bổng', summary: 'Đêm hội trăng rằm tràn ngập tiếng cười cùng múa lân, văn nghệ thiếu nhi và lễ tuyên dương các cháu con đoàn viên đạt thành tích học tập xuất sắc.', gradient: 'linear-gradient(135deg, #d97706, #92400e)' },
  { id: 'act4', title: 'Phong Trào Thi Đua "Lao Động Giỏi - Cải Tiến Kaizen An Toàn 5S"', date: '2026-08-12', tag: 'Thi đua Kaizen', highlight: '86 đề tài Kaizen từ xưởng Đúc, Gia công, Bảo trì', summary: 'Công đoàn phát động phong trào cải tiến góc làm việc an toàn, giảm thao tác thừa và chống nóng tại khu vực lò đúc áp lực, trao thưởng nóng cho 18 tập thể và cá nhân.', gradient: 'linear-gradient(135deg, #0f766e, #115e59)' },
  { id: 'act5', title: 'Chương Trình Du Lịch Nghỉ Mát Hè Sầm Sơn - Hạ Long Cho Đoàn Viên', date: '2026-07-05', tag: 'Văn nghệ - Thể thao', highlight: '3 đợt nghỉ mát 3 ngày 2 đêm • Đêm Gala Dinner', summary: 'Hoạt động nghỉ mát thường niên giúp công nhân viên tái tạo sức lao động, gắn kết gia đình YPMV với chương trình Team Building bãi biển sôi động.', gradient: 'linear-gradient(135deg, #0284c7, #0369a1)' },
  { id: 'act6', title: 'Ngày Hội Hiến Máu Tình Nguyện "Giọt Hồng Yamaha - Sẻ Chia Sự Sống"', date: '2026-05-19', tag: 'Thiện nguyện - Xã hội', highlight: '380 đơn vị máu hiến tặng Viện Huyết học TW', summary: 'Hàng trăm đoàn viên công đoàn các bộ phận nhiệt tình đăng ký hiến máu nhân đạo, lan tỏa nét đẹp văn hóa sẻ chia vì cộng đồng của tập thể YPMV.', gradient: 'linear-gradient(135deg, #be123c, #881337)' },
];

// State
let isServerMode = false;
let serverToken = localStorage.getItem(STORAGE_KEYS.SERVER_TOKEN) || '';
let departments = [];
let serverDeptCounts = {};
let serverTotalMembersCount = 0;
let members = [];
let plans = [];
let policies = [];
let activities = [];
let admins = [];
let welfareRequests = [];
let currentAdmin = null;
let selectedDepartment = 'ALL';
let selectedPlanCategory = 'ALL';
let selectedWelfareFilter = 'ALL';

document.addEventListener('DOMContentLoaded', async () => {
  await loadAllData();
  setupNavigation();
  setupExcelImport();
  renderAll();
  if (window.lucide) {
    lucide.createIcons();
  }
});

async function apiRequest(url, method = 'GET', bodyObj = null) {
  const headers = { 'Content-Type': 'application/json' };
  if (serverToken) headers['Authorization'] = `Bearer ${serverToken}`;
  const opts = { method, headers, credentials: 'same-origin' };
  if (bodyObj) opts.body = JSON.stringify(bodyObj);
  const res = await fetch(url, opts);
  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || `Lỗi máy chủ (${res.status})`);
  }
  return data;
}

async function loadAllData() {
  const modeEl = document.getElementById('server-mode-indicator');
  if (window.location.protocol.startsWith('http')) {
    try {
      const data = await apiRequest('/api/bootstrap', 'GET');
      isServerMode = true;
      departments = data.departments || [...DEFAULT_DEPARTMENTS];
      serverDeptCounts = data.departmentCounts || {};
      serverTotalMembersCount = data.totalMembersCount ?? 0;
      members = Array.isArray(data.members) ? data.members : [];
      plans = data.plans || [...DEFAULT_PLANS];
      policies = data.policies || [...DEFAULT_POLICIES];
      activities = data.activities || [...DEFAULT_ACTIVITIES];
      admins = data.admins || [];
      welfareRequests = Array.isArray(data.welfareRequests) ? data.welfareRequests : [];
      currentAdmin = data.authenticated ? data.currentAdmin : null;
      if (modeEl) {
        modeEl.innerHTML = `<strong style="color:#4ade80;">● Đang chạy Host Server Bảo mật</strong>`;
      }
      return;
    } catch (err) {
      console.warn('Không kết nối được API Server, chuyển sang chế độ Local:', err);
    }
  }

  isServerMode = false;
  if (modeEl) {
    modeEl.innerHTML = `<span style="color:#fbbf24;">● Chế độ mở file trực tiếp (Offline)</span>`;
  }

  departments = JSON.parse(localStorage.getItem(STORAGE_KEYS.DEPARTMENTS)) || [...DEFAULT_DEPARTMENTS];
  members = JSON.parse(localStorage.getItem(STORAGE_KEYS.MEMBERS)) || [...DEFAULT_MEMBERS];
  plans = JSON.parse(localStorage.getItem(STORAGE_KEYS.PLANS)) || [...DEFAULT_PLANS];
  policies = JSON.parse(localStorage.getItem(STORAGE_KEYS.POLICIES)) || [...DEFAULT_POLICIES];
  activities = JSON.parse(localStorage.getItem(STORAGE_KEYS.ACTIVITIES)) || [...DEFAULT_ACTIVITIES];
  admins = JSON.parse(localStorage.getItem(STORAGE_KEYS.ADMINS)) || [...DEFAULT_ADMINS];
  welfareRequests = JSON.parse(localStorage.getItem(STORAGE_KEYS.WELFARE_REQUESTS)) || [];

  admins = admins.map((a) => {
    const migrated = { ...a };
    if (migrated.username && migrated.username.toLowerCase() === 'duonglap') {
      migrated.id = 'adm_root';
      migrated.username = 'nguyenvanhop';
      migrated.fullName = 'Đ/c Nguyễn Văn Hợp';
      migrated.role = 'PCT Tài chính (Người kiểm tra 2)';
      migrated.approvalRole = 'checker2';
      migrated.isPrimary = true;
    }
    if (!migrated.approvalRole) {
      migrated.approvalRole = 'requester';
    }
    if (migrated.password && !migrated.passwordHash) {
      migrated.passwordHash = migrated.password.startsWith('sha256$')
        ? migrated.password
        : hashPasswordSync(migrated.password);
      delete migrated.password;
    }
    return migrated;
  });

  DEFAULT_ADMINS.forEach((def) => {
    const exists = admins.some((a) => a.username && a.username.toLowerCase() === def.username.toLowerCase());
    if (!exists && admins.length < MAX_ADMIN_ACCOUNTS) {
      admins.push({ ...def });
    }
  });
  if (admins.length > MAX_ADMIN_ACCOUNTS) admins = admins.slice(0, MAX_ADMIN_ACCOUNTS);
  localStorage.setItem(STORAGE_KEYS.ADMINS, JSON.stringify(admins));

  const savedSession = JSON.parse(localStorage.getItem(STORAGE_KEYS.SESSION) || 'null');
  if (savedSession && savedSession.id && savedSession.token && savedSession.expiresAt) {
    if (Date.now() < savedSession.expiresAt) {
      const found = admins.find((a) => a.id === savedSession.id);
      const expectedToken = found ? hashPasswordSync(found.id + ':' + found.username + ':' + found.passwordHash) : '';
      if (found && savedSession.token === expectedToken) {
        currentAdmin = found;
        refreshSessionExpiry();
      } else {
        localStorage.removeItem(STORAGE_KEYS.SESSION);
      }
    } else {
      localStorage.removeItem(STORAGE_KEYS.SESSION);
    }
  }
}

async function saveAllData() {
  if (isServerMode) {
    try {
      const res = await apiRequest('/api/sync', 'POST', {
        departments,
        members,
        plans,
        policies,
        activities,
      });
      if (res.departmentCounts) serverDeptCounts = res.departmentCounts;
      if (typeof res.totalMembersCount === 'number') serverTotalMembersCount = res.totalMembersCount;
    } catch (err) {
      showToast(err.message || 'Lỗi đồng bộ lên máy chủ Host!');
    }
    return;
  }

  localStorage.setItem(STORAGE_KEYS.DEPARTMENTS, JSON.stringify(departments));
  localStorage.setItem(STORAGE_KEYS.MEMBERS, JSON.stringify(members));
  localStorage.setItem(STORAGE_KEYS.PLANS, JSON.stringify(plans));
  localStorage.setItem(STORAGE_KEYS.WELFARE_REQUESTS, JSON.stringify(welfareRequests));
  localStorage.setItem(STORAGE_KEYS.POLICIES, JSON.stringify(policies));
  localStorage.setItem(STORAGE_KEYS.ACTIVITIES, JSON.stringify(activities));
  localStorage.setItem(STORAGE_KEYS.ADMINS, JSON.stringify(admins));
}

function getDeptMemberCount(dept) {
  if (isServerMode && !currentAdmin) {
    return serverDeptCounts[dept] || 0;
  }
  return members.filter((m) => m.dept === dept).length;
}

function getTotalMemberCount() {
  if (isServerMode && !currentAdmin) {
    return serverTotalMembersCount;
  }
  return members.length;
}

function closeMobileSidebar() {
  document.getElementById('sidebar')?.classList.remove('open');
  document.getElementById('sidebar-backdrop')?.classList.remove('open');
}

function setupNavigation() {
  document.querySelectorAll('.nav-link').forEach((link) => {
    link.addEventListener('click', (e) => {
      e.preventDefault();
      const tab = link.getAttribute('data-tab');
      switchTab(tab);
    });
  });

  const mobileToggle = document.getElementById('mobile-toggle');
  if (mobileToggle) {
    mobileToggle.addEventListener('click', () => {
      const sb = document.getElementById('sidebar');
      const bd = document.getElementById('sidebar-backdrop');
      const isOpen = sb.classList.toggle('open');
      if (bd) bd.classList.toggle('open', isOpen);
    });
  }
}

const TAB_TITLES = {
  overview: 'Tổng quan Cổng thông tin Công đoàn YPMV',
  members: '1. Danh sách Công đoàn viên theo Bộ phận (Nhập/Xuất Excel)',
  plans: '2. Kế hoạch Hoạt động Công đoàn Sắp tới',
  policies: '3. Chính sách & Chế độ Phúc lợi Công đoàn',
  activities: '4. Hoạt động & Phong trào Công đoàn YPMV',
  admins: '5. Đăng nhập & Quản lý Tài khoản Quản trị (Tối đa 10 TK)',
};

function switchTab(tabName, deptFilter = null) {
  document.querySelectorAll('.nav-link').forEach((l) => {
    l.classList.toggle('active', l.getAttribute('data-tab') === tabName);
  });
  document.querySelectorAll('.m-nav-item').forEach((m) => {
    m.classList.toggle('active', m.getAttribute('data-tab') === tabName);
  });
  document.querySelectorAll('.tab-panel').forEach((p) => {
    p.classList.toggle('active', p.id === `tab-${tabName}`);
  });

  document.getElementById('page-title').textContent = TAB_TITLES[tabName] || TAB_TITLES.overview;
  closeMobileSidebar();

  if (deptFilter !== null) {
    selectedDepartment = deptFilter;
    renderDepartmentPills();
    renderMembersTable();
  }
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

function renderAll() {
  renderAuthUI();
  renderOverviewStats();
  renderDepartmentPills();
  renderDepartmentSelectOptions();
  renderMembersTable();
  renderPlans();
  renderPolicies();
  renderActivities();
  renderAdminsSection();
  renderWelfareRequests();
  if (window.lucide) {
    lucide.createIcons();
  }
}

function renderOverviewStats() {
  const totalCount = getTotalMemberCount();
  const navCountEl = document.getElementById('nav-member-count');
  if (navCountEl) navCountEl.textContent = totalCount;
  const heroTotalEl = document.getElementById('hero-total-members');
  if (heroTotalEl) heroTotalEl.textContent = totalCount;

  // Render Biểu đồ hình cột số lượng Công đoàn viên các bộ phận trong Hero Card
  const chartEl = document.getElementById('hero-dept-bar-chart');
  if (chartEl) {
    const deptCounts = departments.map((dept) => ({
      dept,
      count: getDeptMemberCount(dept),
    }));
    const maxCount = Math.max(...deptCounts.map((d) => d.count), 1);

    chartEl.innerHTML = deptCounts
      .map(({ dept, count }) => {
        const heightPct = Math.max(Math.round((count / maxCount) * 100), 10);
        return `
          <div class="hero-bar-col" onclick="switchTab('members', '${escapeHtml(dept)}')" title="${escapeHtml(dept)}: ${count} đoàn viên">
            <span class="hero-bar-val">${count}</span>
            <div class="hero-bar-track">
              <div class="hero-bar-fill" style="height: ${heightPct}%;"></div>
            </div>
            <span class="hero-bar-label">${escapeHtml(dept)}</span>
          </div>
        `;
      })
      .join('');
  }

  const container = document.getElementById('overview-dept-cards');
  if (container) {
    container.innerHTML = departments
      .map((dept) => {
        const count = getDeptMemberCount(dept);
        return `
          <div class="dept-mini-card" onclick="switchTab('members', '${escapeHtml(dept)}')">
            <h4>${escapeHtml(dept)}</h4>
            <div class="dept-count">
              <span class="text-muted">Số đoàn viên</span>
              <strong>${count}</strong>
            </div>
          </div>
        `;
      })
      .join('');
  }
}

// ============================================================================
// MỤC 1: DANH SÁCH CÔNG ĐOÀN VIÊN THEO 6 SHEET & NHẬP/XUẤT EXCEL 6 SHEET CHUẨN MẪU
// ============================================================================

const SHEET_BANNERS = {
  'Prod 1': 'DANH SÁCH NHẬN BÁNH TRUNG THU XƯỞNG PROD 1',
  'Prod 2': 'DANH SÁCH NHẬN BÁNH TRUNG THU XƯỞNG PROD 2',
  'Prod 3': 'DANH SÁCH NHẬN BÁNH TRUNG THU XƯỞNG PROD 3',
  'MT': 'DANH SÁCH NHẬN BÁNH TRUNG THU MT',
  'Bảo an': 'DANH SÁCH NHẬN BÁNH TRUNG THU Bảo An',
  'Văn Phòng': 'DANH SÁCH NHẬN BÁNH TRUNG THU VĂN PHÒNG',
};

const SHEET_DEFAULT_DEPARTMENT_COL = {
  'Prod 1': 'Production 1',
  'Prod 2': 'Production 2',
  'Prod 3': 'Production 3',
  'MT': 'Maintenance',
  'Bảo an': 'Utility',
  'Văn Phòng': 'General Affairs',
};

function normalizeSheetName(rawName) {
  const s = String(rawName || '').trim();
  const lower = s.toLowerCase();
  if (lower === 'prod 1' || lower === 'production 1' || lower === 'prod1') return 'Prod 1';
  if (lower === 'prod 2' || lower === 'production 2' || lower === 'prod2') return 'Prod 2';
  if (lower === 'prod 3' || lower === 'production 3' || lower === 'prod3') return 'Prod 3';
  if (lower === 'mt' || lower === 'maintenance') return 'MT';
  if (lower === 'bảo an' || lower === 'bao an' || lower === 'utility') return 'Bảo an';
  if (lower === 'văn phòng' || lower === 'van phong' || lower === 'office') return 'Văn Phòng';
  return s;
}

function renderDepartmentPills() {
  const pillsContainer = document.getElementById('dept-pills');
  const allCount = getTotalMemberCount();

  let html = `
    <button class="dept-pill ${selectedDepartment === 'ALL' ? 'active' : ''}" onclick="selectDepartment('ALL')">
      <span>Tất cả 6 Sheet</span>
      <span class="count">${allCount}</span>
    </button>
  `;

  departments.forEach((dept) => {
    const count = getDeptMemberCount(dept);
    const isActive = selectedDepartment === dept ? 'active' : '';
    html += `
      <button class="dept-pill ${isActive}" onclick="selectDepartment('${escapeHtml(dept)}')">
        <span>Sheet: ${escapeHtml(dept)}</span>
        <span class="count">${count}</span>
      </button>
    `;
  });

  pillsContainer.innerHTML = html;
}

function updateSheetSubFilters() {
  const deptColSelect = document.getElementById('filter-department-col');
  const shopSelect = document.getElementById('filter-shop');
  const groupSelect = document.getElementById('filter-group');
  if (!deptColSelect || !shopSelect || !groupSelect) return;

  const prevDeptCol = deptColSelect.value || 'ALL';
  const prevShop = shopSelect.value || 'ALL';
  const prevGroup = groupSelect.value || 'ALL';

  const baseList =
    selectedDepartment === 'ALL'
      ? members
      : members.filter((m) => m.dept === selectedDepartment);

  const distinctDeptCols = Array.from(
    new Set(baseList.map((m) => (m.department || '').trim()).filter(Boolean))
  ).sort();
  const distinctShops = Array.from(
    new Set(baseList.map((m) => (m.shop || m.team || '').trim()).filter(Boolean))
  ).sort();
  const distinctGroups = Array.from(
    new Set(baseList.map((m) => (m.group || '').trim()).filter(Boolean))
  ).sort();

  deptColSelect.innerHTML =
    `<option value="ALL">Tất cả Department (${distinctDeptCols.length})</option>` +
    distinctDeptCols.map((v) => `<option value="${escapeHtml(v)}">${escapeHtml(v)}</option>`).join('');
  shopSelect.innerHTML =
    `<option value="ALL">Tất cả Shop (${distinctShops.length})</option>` +
    distinctShops.map((v) => `<option value="${escapeHtml(v)}">${escapeHtml(v)}</option>`).join('');
  groupSelect.innerHTML =
    `<option value="ALL">Tất cả Group (${distinctGroups.length})</option>` +
    distinctGroups.map((v) => `<option value="${escapeHtml(v)}">${escapeHtml(v)}</option>`).join('');

  if (distinctDeptCols.includes(prevDeptCol)) deptColSelect.value = prevDeptCol;
  if (distinctShops.includes(prevShop)) shopSelect.value = prevShop;
  if (distinctGroups.includes(prevGroup)) groupSelect.value = prevGroup;
}

function selectDepartment(dept) {
  selectedDepartment = dept;
  const deptColSelect = document.getElementById('filter-department-col');
  const shopSelect = document.getElementById('filter-shop');
  const groupSelect = document.getElementById('filter-group');
  if (deptColSelect) deptColSelect.value = 'ALL';
  if (shopSelect) shopSelect.value = 'ALL';
  if (groupSelect) groupSelect.value = 'ALL';
  renderDepartmentPills();
  updateSheetSubFilters();
  renderMembersTable();
}

function renderDepartmentSelectOptions() {
  const select = document.getElementById('m-dept');
  if (!select) return;
  select.innerHTML = departments
    .map((d) => `<option value="${escapeHtml(d)}">${escapeHtml(d)}</option>`)
    .join('');
}

function onMemberSheetSelectChange() {
  const sheetVal = document.getElementById('m-dept')?.value || '';
  const deptColInput = document.getElementById('m-department-col');
  if (deptColInput && !deptColInput.value.trim() && SHEET_DEFAULT_DEPARTMENT_COL[sheetVal]) {
    deptColInput.value = SHEET_DEFAULT_DEPARTMENT_COL[sheetVal];
  }
}

function getFilteredMembers() {
  const query = (document.getElementById('member-search')?.value || '').trim().toLowerCase();
  const deptColFilter = document.getElementById('filter-department-col')?.value || 'ALL';
  const shopFilter = document.getElementById('filter-shop')?.value || 'ALL';
  const groupFilter = document.getElementById('filter-group')?.value || 'ALL';

  return members.filter((m) => {
    const matchSheet = selectedDepartment === 'ALL' || m.dept === selectedDepartment;
    const mDeptCol = (m.department || '').trim();
    const mShop = (m.shop || m.team || '').trim();
    const mGroup = (m.group || '').trim();

    const matchDeptCol = deptColFilter === 'ALL' || mDeptCol === deptColFilter;
    const matchShop = shopFilter === 'ALL' || mShop === shopFilter;
    const matchGroup = groupFilter === 'ALL' || mGroup === groupFilter;

    const matchQuery =
      !query ||
      (m.code && m.code.toLowerCase().includes(query)) ||
      (m.name && m.name.toLowerCase().includes(query)) ||
      (mDeptCol && mDeptCol.toLowerCase().includes(query)) ||
      (mShop && mShop.toLowerCase().includes(query)) ||
      (mGroup && mGroup.toLowerCase().includes(query)) ||
      (m.note && m.note.toLowerCase().includes(query)) ||
      (m.dept && m.dept.toLowerCase().includes(query));

    return matchSheet && matchDeptCol && matchShop && matchGroup && matchQuery;
  });
}

function renderMembersTable() {
  const guestGrid = document.getElementById('members-guest-dept-grid');
  if (guestGrid) {
    guestGrid.innerHTML = departments
      .map((dept) => {
        const count = getDeptMemberCount(dept);
        const isSelected = selectedDepartment === dept;
        return `
          <div class="dept-mini-card" style="${isSelected ? 'border-color: var(--yamaha-red); background: #fff0f3;' : ''}" onclick="selectDepartment('${escapeHtml(dept)}')">
            <h4>Sheet: ${escapeHtml(dept)}</h4>
            <div class="dept-count">
              <span class="text-muted">Số công đoàn viên</span>
              <strong>${count} đoàn viên</strong>
            </div>
          </div>
        `;
      })
      .join('');
  }

  const tbody = document.getElementById('members-tbody');
  if (!tbody) return;

  if (!currentAdmin) {
    tbody.innerHTML = '';
    return;
  }

  updateSheetSubFilters();
  const filtered = getFilteredMembers();
  const summaryEl = document.getElementById('current-filter-summary');
  if (summaryEl) {
    const deptLabel = selectedDepartment === 'ALL' ? 'Tất cả 6 Sheet (Toàn công ty)' : `Sheet ${selectedDepartment}`;
    summaryEl.innerHTML = `Đang xem: <strong>${escapeHtml(deptLabel)}</strong> — Hiển thị <strong>${filtered.length}</strong> / ${members.length} công đoàn viên`;
  }

  if (filtered.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="9" style="text-align:center; padding: 36px; color: #64748b;">
          Không tìm thấy công đoàn viên nào phù hợp với bộ lọc hiện tại.
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = filtered
    .map((m, idx) => {
      const deptCol = m.department || SHEET_DEFAULT_DEPARTMENT_COL[m.dept] || m.dept || '-';
      const shopVal = m.shop || m.team || '-';
      const groupVal = m.group || '-';
      const noteVal = m.note || '';

      return `
        <tr>
          <td>${idx + 1}</td>
          <td><span class="emp-code">${escapeHtml(m.code || '')}</span></td>
          <td><strong>${escapeHtml(m.name || '')}</strong></td>
          <td><span class="dept-badge">${escapeHtml(m.dept || '')}</span></td>
          <td>${escapeHtml(deptCol)}</td>
          <td>${escapeHtml(shopVal)}</td>
          <td>${escapeHtml(groupVal)}</td>
          <td>${escapeHtml(noteVal)}</td>
          <td>
            <div class="row-actions">
              <button class="btn-action" onclick="editMember('${m.id}')" title="Sửa thông tin">
                <i data-lucide="pencil"></i>
              </button>
              <button class="btn-action" onclick="deleteMember('${m.id}')" title="Xóa đoàn viên">
                <i data-lucide="trash-2"></i>
              </button>
            </div>
          </td>
        </tr>
      `;
    })
    .join('');

  if (window.lucide) {
    lucide.createIcons();
  }
}

function openMemberModal(member = null) {
  if (!requireAdminAuth('cập nhật danh sách công đoàn viên')) return;
  renderDepartmentSelectOptions();
  const modalTitle = document.getElementById('member-modal-title');
  const form = document.getElementById('member-form');
  form.reset();

  if (member) {
    modalTitle.textContent = 'Cập nhật thông tin Công đoàn viên';
    document.getElementById('member-id').value = member.id;
    document.getElementById('m-code').value = member.code || '';
    document.getElementById('m-name').value = member.name || '';
    document.getElementById('m-dept').value = member.dept || departments[0];
    document.getElementById('m-department-col').value = member.department || SHEET_DEFAULT_DEPARTMENT_COL[member.dept] || '';
    document.getElementById('m-shop').value = member.shop || member.team || '';
    document.getElementById('m-group').value = member.group || '';
    document.getElementById('m-note').value = member.note || '';
  } else {
    modalTitle.textContent = 'Thêm Công đoàn viên mới vào Sheet';
    document.getElementById('member-id').value = '';
    const defaultSheet = selectedDepartment !== 'ALL' ? selectedDepartment : departments[0];
    document.getElementById('m-dept').value = defaultSheet;
    document.getElementById('m-department-col').value = SHEET_DEFAULT_DEPARTMENT_COL[defaultSheet] || '';
  }

  document.getElementById('member-modal').classList.add('open');
}

async function saveMemberForm(e) {
  e.preventDefault();
  if (!requireAdminAuth('lưu thông tin công đoàn viên')) return;
  const id = document.getElementById('member-id').value;
  const sheetName = document.getElementById('m-dept').value;
  const memberData = {
    id: id || 'm_' + Date.now(),
    code: sanitizeExcelCellText(document.getElementById('m-code').value),
    name: sanitizeExcelCellText(document.getElementById('m-name').value),
    dept: sheetName,
    department: sanitizeExcelCellText(document.getElementById('m-department-col').value || SHEET_DEFAULT_DEPARTMENT_COL[sheetName] || sheetName),
    shop: sanitizeExcelCellText(document.getElementById('m-shop').value),
    group: sanitizeExcelCellText(document.getElementById('m-group').value),
    note: sanitizeExcelCellText(document.getElementById('m-note').value),
  };

  if (id) {
    const index = members.findIndex((m) => m.id === id);
    if (index > -1) members[index] = memberData;
    showToast(`Đã cập nhật đoàn viên ${memberData.name} (${memberData.code})`);
  } else {
    members.push(memberData);
    showToast(`Đã thêm đoàn viên ${memberData.name} vào Sheet ${memberData.dept}`);
  }

  await saveAllData();
  closeModal('member-modal');
  renderAll();
}

function editMember(id) {
  if (!requireAdminAuth('chỉnh sửa công đoàn viên')) return;
  const m = members.find((item) => item.id === id);
  if (m) openMemberModal(m);
}

async function deleteMember(id) {
  if (!requireAdminAuth('xóa công đoàn viên')) return;
  const m = members.find((item) => item.id === id);
  if (!m) return;
  if (confirm(`Bạn có chắc muốn xóa đoàn viên "${m.name}" (${m.code}) khỏi Sheet ${m.dept}?`)) {
    members = members.filter((item) => item.id !== id);
    await saveAllData();
    renderAll();
    showToast(`Đã xóa đoàn viên ${m.name}`);
  }
}

async function openAddDeptModal() {
  if (!requireAdminAuth('thêm Sheet / Bộ phận mới')) return;
  const newDept = prompt('Nhập tên Sheet / Bộ phận mới của Công ty YPMV:');
  if (newDept && newDept.trim()) {
    const clean = sanitizeExcelCellText(newDept.trim());
    if (!departments.includes(clean)) {
      departments.push(clean);
      await saveAllData();
      renderAll();
      showToast(`Đã thêm Sheet / Bộ phận: ${clean}`);
    } else {
      showToast('Sheet / Bộ phận này đã tồn tại trong danh sách!');
    }
  }
}

async function resetDefaultMembers() {
  if (!requireAdminAuth('khôi phục dữ liệu gốc 6 Sheet')) return;
  if (confirm('Khôi phục danh sách công đoàn viên về dữ liệu chuẩn 6 Sheet (1.398 công đoàn viên YPMV)?')) {
    departments = [...DEFAULT_DEPARTMENTS];
    members = DEFAULT_MEMBERS.map((m) => ({ ...m }));
    selectedDepartment = 'ALL';
    await saveAllData();
    renderAll();
    showToast('Đã khôi phục 1.398 công đoàn viên chuẩn 6 Sheet YPMV.');
  }
}

// ============================================================================
// EXCEL IMPORT & EXPORT CHUẨN MẪU 6 SHEET (Prod 1, Prod 2, Prod 3, MT, Bảo an, Văn Phòng + Tổng số lượng)
// ============================================================================

function parseWorksheetByTemplate(worksheet, rawSheetName) {
  const sheetName = normalizeSheetName(rawSheetName);
  const aoa = XLSX.utils.sheet_to_json(worksheet, { header: 1, defval: '' });
  if (!aoa || aoa.length === 0) return [];

  // Tìm dòng Header chứa 'Employee ID' hoặc 'Mã NV' hoặc 'Full Name'
  let headerRowIdx = -1;
  let colMap = {
    code: 1,
    name: 2,
    department: 3,
    shop: 4,
    group: -1,
    note: 5,
  };

  for (let r = 0; r < Math.min(aoa.length, 12); r++) {
    const rowCells = (aoa[r] || []).map((c) => String(c || '').trim().toLowerCase());
    const empIdx = rowCells.findIndex((c) => c === 'employee id' || c === 'mã nv' || c === 'ma nv' || c === 'mã nhân viên');
    const nameIdx = rowCells.findIndex((c) => c === 'full name' || c === 'họ và tên' || c === 'ho va ten' || c === 'họ tên');
    if (empIdx !== -1 && nameIdx !== -1) {
      headerRowIdx = r;
      colMap.code = empIdx;
      colMap.name = nameIdx;
      colMap.department = rowCells.findIndex((c) => c === 'department' || c === 'phòng ban' || c === 'bộ phận');
      colMap.shop = rowCells.findIndex((c) => c === 'shop' || c === 'xưởng' || c === 'tổ' || c === 'tổ/chuyền');
      colMap.group = rowCells.findIndex((c) => c === 'group' || c === 'nhóm' || c === 'chuyền');
      colMap.note = rowCells.findIndex((c) => c.includes('ký nhận') || c.includes('ky nhan') || c.includes('ghi chú'));
      break;
    }
  }

  if (headerRowIdx === -1) return [];

  const parsedMembers = [];
  let sttCounter = 0;

  for (let r = headerRowIdx + 1; r < aoa.length; r++) {
    const row = aoa[r] || [];
    const code = String(row[colMap.code] ?? '').trim();
    const name = String(row[colMap.name] ?? '').trim();
    if (!code || !name) continue;
    // Bỏ qua nếu là dòng tổng kết
    if (code.toLowerCase() === 'tổng' || code.toLowerCase() === 'total') continue;

    sttCounter++;
    const departmentVal = colMap.department >= 0 ? String(row[colMap.department] ?? '').trim() : (SHEET_DEFAULT_DEPARTMENT_COL[sheetName] || sheetName);
    const shopVal = colMap.shop >= 0 ? String(row[colMap.shop] ?? '').trim() : '';
    const groupVal = colMap.group >= 0 ? String(row[colMap.group] ?? '').trim() : '';
    const noteVal = colMap.note >= 0 ? String(row[colMap.note] ?? '').trim() : '';

    parsedMembers.push({
      id: `${sheetName}_${sttCounter}_${code}`,
      stt: sttCounter,
      code: sanitizeExcelCellText(code),
      name: sanitizeExcelCellText(name),
      dept: sheetName,
      department: sanitizeExcelCellText(departmentVal),
      shop: sanitizeExcelCellText(shopVal),
      group: sanitizeExcelCellText(groupVal),
      note: sanitizeExcelCellText(noteVal),
    });
  }

  return parsedMembers;
}

function setupExcelImport() {
  const fileInput = document.getElementById('excel-upload-input');
  if (!fileInput) return;

  fileInput.addEventListener('change', (e) => {
    if (!requireAdminAuth('nhập danh sách từ file Excel')) {
      fileInput.value = '';
      return;
    }
    const file = e.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = async function (evt) {
      try {
        const data = new Uint8Array(evt.target.result);
        const workbook = XLSX.read(data, { type: 'array' });

        const skipSheets = new Set(['tổng số lượng', 'tong so luong', 'sheet2', 'setup']);
        let allParsed = [];
        let matchedSheets = [];

        workbook.SheetNames.forEach((rawSheetName) => {
          if (skipSheets.has(rawSheetName.trim().toLowerCase())) return;
          const ws = workbook.Sheets[rawSheetName];
          const sheetMembers = parseWorksheetByTemplate(ws, rawSheetName);
          if (sheetMembers.length > 0) {
            const normName = normalizeSheetName(rawSheetName);
            if (!matchedSheets.includes(normName)) matchedSheets.push(normName);
            allParsed = allParsed.concat(sheetMembers);
          }
        });

        if (allParsed.length === 0) {
          showToast('Không tìm thấy dữ liệu hợp lệ (cần có cột Employee ID và Full Name)!');
          return;
        }

        // Nếu file có nhiều sheet (VD: đủ 6 sheet), hỏi người dùng muốn thay thế đồng bộ toàn bộ hay gộp thêm
        if (matchedSheets.length >= 2) {
          departments = [...DEFAULT_DEPARTMENTS];
          matchedSheets.forEach((s) => {
            if (!departments.includes(s)) departments.push(s);
          });
          members = allParsed;
          await saveAllData();
          renderAll();
          showToast(`Đã nạp thành công ${allParsed.length} công đoàn viên từ ${matchedSheets.length} Sheet (${matchedSheets.join(', ')})!`);
        } else {
          // Nếu chỉ tải 1 sheet lẻ, cập nhật riêng các đoàn viên của sheet đó hoặc theo Employee ID
          let importedCount = 0;
          let updatedCount = 0;
          allParsed.forEach((mObj) => {
            if (!departments.includes(mObj.dept)) departments.push(mObj.dept);
            const existingIdx = members.findIndex(
              (m) => m.code.toLowerCase() === mObj.code.toLowerCase() && m.dept === mObj.dept
            );
            if (existingIdx > -1) {
              mObj.id = members[existingIdx].id;
              members[existingIdx] = mObj;
              updatedCount++;
            } else {
              members.push(mObj);
              importedCount++;
            }
          });
          await saveAllData();
          renderAll();
          showToast(`Nhập Sheet "${matchedSheets[0]}" thành công: Thêm mới ${importedCount}, cập nhật ${updatedCount} đoàn viên!`);
        }
      } catch (err) {
        console.error(err);
        showToast('Lỗi đọc file Excel. Vui lòng kiểm tra định dạng .xlsx / .xls / .csv');
      } finally {
        fileInput.value = '';
      }
    };
    reader.readAsArrayBuffer(file);
  });
}

function buildWorksheetForSheet(sheetName, sheetMembers) {
  const banner = SHEET_BANNERS[sheetName] || `DANH SÁCH CÔNG ĐOÀN VIÊN XƯỞNG ${sheetName.toUpperCase()}`;
  const isProd2 = sheetName === 'Prod 2';
  const isBaoAn = sheetName === 'Bảo an';

  let aoa = [];
  if (isProd2) {
    aoa.push([banner, '', '', '', '', '', '']);
    aoa.push(['STT', 'Employee ID', 'Full Name', 'Department', 'Shop', 'Group', 'Ký nhận']);
    sheetMembers.forEach((m, i) => {
      aoa.push([
        i + 1,
        sanitizeExcelCellText(m.code),
        sanitizeExcelCellText(m.name),
        sanitizeExcelCellText(m.department || 'Production 2'),
        sanitizeExcelCellText(m.shop || ''),
        sanitizeExcelCellText(m.group || ''),
        sanitizeExcelCellText(m.note || ''),
      ]);
    });
  } else if (isBaoAn) {
    aoa.push([banner, '', '', '', '']);
    aoa.push(['STT', 'Employee ID', 'Full Name', 'Department', 'Ký nhận']);
    sheetMembers.forEach((m, i) => {
      aoa.push([
        i + 1,
        sanitizeExcelCellText(m.code),
        sanitizeExcelCellText(m.name),
        sanitizeExcelCellText(m.department || 'Utility'),
        sanitizeExcelCellText(m.note || ''),
      ]);
    });
  } else {
    aoa.push([banner, '', '', '', '', '']);
    aoa.push(['STT', 'Employee ID', 'Full Name', 'Department', 'Shop', 'Ký nhận']);
    sheetMembers.forEach((m, i) => {
      aoa.push([
        i + 1,
        sanitizeExcelCellText(m.code),
        sanitizeExcelCellText(m.name),
        sanitizeExcelCellText(m.department || SHEET_DEFAULT_DEPARTMENT_COL[sheetName] || sheetName),
        sanitizeExcelCellText(m.shop || ''),
        sanitizeExcelCellText(m.note || ''),
      ]);
    });
  }

  const ws = XLSX.utils.aoa_to_sheet(aoa);
  ws['!cols'] = isProd2
    ? [{ wch: 6 }, { wch: 14 }, { wch: 26 }, { wch: 22 }, { wch: 24 }, { wch: 20 }, { wch: 14 }]
    : isBaoAn
    ? [{ wch: 6 }, { wch: 14 }, { wch: 26 }, { wch: 18 }, { wch: 14 }]
    : [{ wch: 6 }, { wch: 14 }, { wch: 26 }, { wch: 24 }, { wch: 26 }, { wch: 14 }];
  return ws;
}

function buildSummaryWorksheet(targetSheets, sourceMembers) {
  const aoa = [
    ['STT', 'Xưởng', 'Số lượng CBCNV', 'Nhân viên thử việc YPMV', 'Nhân viên không phải là đoàn viên YPMV', 'SL CBCNV nhận bánh trung thu'],
  ];
  let totalUnion = 0;
  targetSheets.forEach((sName, idx) => {
    const count = sourceMembers.filter((m) => m.dept === sName).length;
    totalUnion += count;
    const displayLabel = sName === 'Văn Phòng' ? 'Văn phòng' : sName;
    aoa.push([idx + 1, displayLabel, count, 0, 0, count]);
  });
  aoa.push(['', 'Tổng', totalUnion, 0, 0, totalUnion]);

  const ws = XLSX.utils.aoa_to_sheet(aoa);
  ws['!cols'] = [{ wch: 6 }, { wch: 16 }, { wch: 18 }, { wch: 24 }, { wch: 34 }, { wch: 28 }];
  return ws;
}

function exportMembersToExcel() {
  if (!requireAdminAuth('xuất file Excel danh sách công đoàn viên')) return;
  if (typeof XLSX === 'undefined') {
    showToast('Thư viện Excel đang tải, vui lòng thử lại sau giây lát.');
    return;
  }

  if (members.length === 0) {
    showToast('Không có dữ liệu đoàn viên nào để xuất Excel!');
    return;
  }

  const wb = XLSX.utils.book_new();
  const sheetsToExport = selectedDepartment === 'ALL' ? departments : [selectedDepartment];

  sheetsToExport.forEach((sheetName) => {
    const sheetMembers =
      selectedDepartment === 'ALL'
        ? members.filter((m) => m.dept === sheetName)
        : getFilteredMembers();
    const ws = buildWorksheetForSheet(sheetName, sheetMembers);
    XLSX.utils.book_append_sheet(wb, ws, sheetName.slice(0, 31));
  });

  if (selectedDepartment === 'ALL') {
    const summaryWs = buildSummaryWorksheet(departments, members);
    XLSX.utils.book_append_sheet(wb, summaryWs, 'Tổng số lượng');
  }

  const suffix = selectedDepartment === 'ALL' ? '6_Sheet_Toan_Cong_Ty' : `Sheet_${selectedDepartment.replace(/\s+/g, '_')}`;
  const fileName = `Danh_Sach_Cong_Doan_Vien_YPMV_${suffix}_${new Date().toISOString().slice(0, 10)}.xlsx`;
  XLSX.writeFile(wb, fileName);
  showToast(`Đã xuất file Excel chuẩn 6 Sheet: ${fileName}`);
}

function downloadExcelTemplate() {
  if (!requireAdminAuth('tải file Excel mẫu 6 Sheet')) return;
  if (typeof XLSX === 'undefined') return;

  const wb = XLSX.utils.book_new();
  departments.forEach((sheetName) => {
    const sheetMembers = members.filter((m) => m.dept === sheetName);
    const ws = buildWorksheetForSheet(sheetName, sheetMembers);
    XLSX.utils.book_append_sheet(wb, ws, sheetName.slice(0, 31));
  });
  const summaryWs = buildSummaryWorksheet(departments, members);
  XLSX.utils.book_append_sheet(wb, summaryWs, 'Tổng số lượng');

  XLSX.writeFile(wb, 'File_Mau_Danh_Sach_Cong_Doan_YPMV_6_Sheet.xlsx');
  showToast('Đã tải File Excel Mẫu chuẩn 6 Sheet (Prod 1, Prod 2, Prod 3, MT, Bảo an, Văn Phòng + Tổng số lượng).');
}

// ============================================================================
// TRÌNH SOẠN THẢO VĂN BẢN HỖN HỢP & CỬA SỔ ĐỌC CHI TIẾT BÀI VIẾT
// ============================================================================

const RICH_EDITOR_IDS = {
  plan: 'p-rich-editor',
  policy: 'pol-rich-editor',
  activity: 'act-rich-editor',
};

function detectMediaTypeFromUrl(url) {
  const clean = (url || '').trim();
  if (!clean) return 'image';
  if (/^data:video\//i.test(clean)) return 'video';
  if (/\.(mp4|webm|ogg|mov)(\?.*)?$/i.test(clean)) return 'video';
  if (/youtube\.com\/watch\?v=|youtu\.be\/|youtube\.com\/embed\//i.test(clean)) return 'youtube';
  return 'image';
}

function toYoutubeEmbedUrl(url) {
  const regExp = /(?:youtube\.com\/(?:[^/]+\/.+\/|(?:v|e(?:mbed)?)\/|.*[?&]v=)|youtu\.be\/)([^"&?/\s]{11})/i;
  const match = String(url || '').match(regExp);
  return match && match[1] ? `https://www.youtube.com/embed/${match[1]}` : url;
}

function compressImageFile(file) {
  return new Promise((resolve) => {
    const reader = new FileReader();
    reader.onload = (e) => {
      const img = new Image();
      img.onload = () => {
        const maxWidth = 1000;
        let width = img.width;
        let height = img.height;
        if (width > maxWidth) {
          height = Math.round((height * maxWidth) / width);
          width = maxWidth;
        }
        const canvas = document.createElement('canvas');
        canvas.width = width;
        canvas.height = height;
        const ctx = canvas.getContext('2d');
        ctx.drawImage(img, 0, 0, width, height);
        resolve(canvas.toDataURL('image/jpeg', 0.82));
      };
      img.onerror = () => resolve(e.target.result);
      img.src = e.target.result;
    };
    reader.readAsDataURL(file);
  });
}

function readFileAsDataUrl(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = (e) => resolve(e.target.result);
    reader.onerror = (err) => reject(err);
    reader.readAsDataURL(file);
  });
}

function execRichCmd(targetKey, command, value = null) {
  const editor = document.getElementById(RICH_EDITOR_IDS[targetKey]);
  if (!editor) return;
  editor.focus();
  document.execCommand(command, false, value);
}

function buildMediaFigureHtml(type, url, caption = '') {
  let mediaEl = '';
  if (type === 'video') {
    mediaEl = `<video src="${escapeHtml(url)}" controls preload="metadata"></video>`;
  } else if (type === 'youtube') {
    mediaEl = `<iframe src="${escapeHtml(url)}" allowfullscreen></iframe>`;
  } else {
    mediaEl = `<img src="${escapeHtml(url)}" alt="${escapeHtml(caption || 'Hình ảnh Công đoàn YPMV')}" />`;
  }

  const captionText = caption || 'Nhập chú thích ảnh/video tại đây...';
  return `
    <figure class="inline-media-figure">
      ${mediaEl}
      <figcaption class="inline-media-caption">${escapeHtml(captionText)}</figcaption>
    </figure>
    <p><br></p>
  `;
}

function insertHtmlIntoRichEditor(targetKey, htmlSnippet) {
  const editor = document.getElementById(RICH_EDITOR_IDS[targetKey]);
  if (!editor) return;
  editor.focus();

  const sel = window.getSelection();
  if (sel && sel.rangeCount > 0 && editor.contains(sel.anchorNode)) {
    document.execCommand('insertHTML', false, htmlSnippet);
  } else {
    editor.insertAdjacentHTML('beforeend', htmlSnippet);
  }
}

async function insertMediaFilesIntoEditor(event, targetKey) {
  const files = Array.from(event.target.files || []);
  if (!files.length) return;

  for (const file of files) {
    const isVideo = file.type.startsWith('video/');
    if (isVideo && file.size > 15 * 1024 * 1024) {
      showToast(`Video "${file.name}" lớn hơn 15MB, vui lòng chọn video ngắn hơn hoặc dùng nút Chèn Link Video/YouTube!`);
      continue;
    }
    try {
      const dataUrl = isVideo ? await readFileAsDataUrl(file) : await compressImageFile(file);
      const html = buildMediaFigureHtml(isVideo ? 'video' : 'image', dataUrl, file.name.replace(/\.[^.]+$/, ''));
      insertHtmlIntoRichEditor(targetKey, html);
    } catch (err) {
      console.error(err);
      showToast('Không thể chèn tệp vào bài viết.');
    }
  }

  event.target.value = '';
  showToast('Đã chèn Ảnh/Video trực tiếp vào vị trí con trỏ văn bản!');
}

function promptMediaUrlIntoEditor(targetKey) {
  const url = prompt('Dán đường dẫn (Link) Hình ảnh, Video (.mp4) hoặc Link YouTube cần chèn vào văn bản:');
  if (!url || !url.trim()) return;
  const caption = prompt('Nhập chú thích cho Hình ảnh / Video này (bỏ trống nếu không cần):') || '';
  const type = detectMediaTypeFromUrl(url);
  const finalUrl = type === 'youtube' ? toYoutubeEmbedUrl(url.trim()) : url.trim();
  const html = buildMediaFigureHtml(type, finalUrl, caption.trim());
  insertHtmlIntoRichEditor(targetKey, html);
}

function getInitialRichContent(item, summaryText) {
  if (item && item.contentHtml && item.contentHtml.trim()) {
    return sanitizeRichHtml(item.contentHtml);
  }
  const paragraphs = String(summaryText || '')
    .split('\n')
    .filter(Boolean)
    .map((line) => `<p>${escapeHtml(line)}</p>`)
    .join('');

  const legacyMedia = Array.isArray(item?.media)
    ? item.media.map((m) => buildMediaFigureHtml(m.type, m.url, m.caption)).join('')
    : '';

  return sanitizeRichHtml((paragraphs || '<p></p>') + legacyMedia);
}

function openArticleReader(type, id) {
  let item = null;
  let badgeText = '';
  let dateText = '';
  let submetaHtml = '';
  let summaryText = '';

  if (type === 'plan') {
    item = plans.find((p) => p.id === id);
    if (!item) return;
    badgeText = `Kế hoạch • ${item.category}`;
    dateText = `Thời gian dự kiến: ${item.date}`;
    summaryText = item.desc;
    submetaHtml = `
      <span><strong>Trạng thái:</strong> ${escapeHtml(item.status)}</span>
      <span><strong>Địa điểm:</strong> ${escapeHtml(item.location)}</span>
      <span><strong>Thành phần tham gia:</strong> ${escapeHtml(item.participants)}</span>
    `;
  } else if (type === 'policy') {
    item = policies.find((p) => p.id === id);
    if (!item) return;
    badgeText = `Chính sách • ${item.group}`;
    dateText = `Chế độ phúc lợi Công đoàn YPMV`;
    summaryText = item.desc;
    submetaHtml = `
      <span><strong>Mức hưởng / Kinh phí hỗ trợ:</strong> <span style="color:var(--yamaha-red);font-weight:800;">${escapeHtml(item.amount)}</span></span>
    `;
  } else if (type === 'activity') {
    item = activities.find((a) => a.id === id);
    if (!item) return;
    badgeText = `Hoạt động • ${item.tag}`;
    dateText = `Ngày tổ chức: ${item.date}`;
    summaryText = item.summary;
    submetaHtml = `
      <span><strong>Điểm nhấn chương trình:</strong> ${escapeHtml(item.highlight || 'Phong trào Đoàn viên YPMV')}</span>
    `;
  }

  document.getElementById('reader-badge').textContent = badgeText;
  document.getElementById('reader-date').textContent = dateText;
  document.getElementById('reader-title').textContent = item.title;
  document.getElementById('reader-submeta').innerHTML = submetaHtml;
  document.getElementById('reader-content').innerHTML = getInitialRichContent(item, summaryText);

  const footerEl = document.getElementById('reader-footer');
  if (footerEl) {
    let adminBtns = '';
    if (currentAdmin) {
      if (type === 'plan') {
        adminBtns = `<button type="button" class="btn btn-primary" onclick="closeModal('article-reader-modal'); editPlan('${item.id}')"><i data-lucide="pencil"></i> Chỉnh sửa bài viết này</button>`;
      } else if (type === 'policy') {
        adminBtns = `<button type="button" class="btn btn-primary" onclick="closeModal('article-reader-modal'); editPolicy('${item.id}')"><i data-lucide="pencil"></i> Chỉnh sửa chính sách này</button>`;
      } else if (type === 'activity') {
        adminBtns = `<button type="button" class="btn btn-primary" onclick="closeModal('article-reader-modal'); editActivity('${item.id}')"><i data-lucide="pencil"></i> Chỉnh sửa bài viết này</button>`;
      }
    }
    footerEl.innerHTML = `
      ${adminBtns}
      <button type="button" class="btn btn-outline" onclick="closeModal('article-reader-modal')">Đóng cửa sổ đọc</button>
    `;
  }

  document.getElementById('article-reader-modal').classList.add('open');
  if (window.lucide) lucide.createIcons();
}

// ============================================================================
// MỤC 2: KẾ HOẠCH SẮP TỚI
// ============================================================================

function setPlanFilter(category, btnEl) {
  selectedPlanCategory = category;
  document.querySelectorAll('.plans-filter-bar .chip').forEach((c) => c.classList.remove('active'));
  if (btnEl) btnEl.classList.add('active');
  renderPlans();
}

function renderPlans() {
  const container = document.getElementById('plans-container');
  const list = selectedPlanCategory === 'ALL'
    ? plans
    : plans.filter((p) => p.category === selectedPlanCategory);

  if (list.length === 0) {
    container.innerHTML = `<div class="card" style="grid-column: 1 / -1; text-align:center; color:#64748b;">Chưa có kế hoạch nào trong danh mục này.</div>`;
    return;
  }

  container.innerHTML = list
    .map(
      (p) => `
      <div class="plan-card clickable" onclick="openArticleReader('plan', '${p.id}')">
        <div>
          <div class="plan-card-top">
            <span class="plan-date-box"><i data-lucide="calendar"></i> ${escapeHtml(p.date)}</span>
            <span class="plan-status">${escapeHtml(p.status)}</span>
          </div>
          <h4>${escapeHtml(p.title)}</h4>
          <p class="post-text-content">${escapeHtml(p.desc)}</p>
          <span class="read-more-link"><i data-lucide="book-open"></i> Nhấn để xem bài viết chi tiết (Văn bản, Ảnh & Video)</span>
        </div>
        <div>
          <div class="plan-meta" style="margin-top: 12px;">
            <span><i data-lucide="tag"></i> Chuyên mục: <strong>${escapeHtml(p.category)}</strong></span>
            <span><i data-lucide="map-pin"></i> Địa điểm: ${escapeHtml(p.location)}</span>
            <span><i data-lucide="users"></i> Đối tượng: ${escapeHtml(p.participants)}</span>
          </div>
          ${
            currentAdmin
              ? `
            <div class="card-admin-actions" onclick="event.stopPropagation()">
              <button class="btn-card-action" onclick="editPlan('${p.id}')">
                <i data-lucide="pencil"></i> Chỉnh sửa
              </button>
              <button class="btn-card-action danger" onclick="deletePlan('${p.id}')">
                <i data-lucide="trash-2"></i> Xóa
              </button>
            </div>
          `
              : ''
          }
        </div>
      </div>
    `
    )
    .join('');

  if (window.lucide) lucide.createIcons();
}

function openPlanModal(plan = null) {
  if (!requireAdminAuth('cập nhật kế hoạch công đoàn')) return;
  const form = document.getElementById('plan-form');
  form.reset();
  const titleEl = document.getElementById('plan-modal-title');
  const editor = document.getElementById(RICH_EDITOR_IDS.plan);

  if (plan) {
    if (titleEl) titleEl.textContent = 'Chỉnh sửa Kế hoạch Công đoàn';
    document.getElementById('plan-id').value = plan.id;
    document.getElementById('p-title').value = plan.title || '';
    document.getElementById('p-date').value = plan.date || '';
    document.getElementById('p-category').value = plan.category || 'Chăm lo phúc lợi';
    document.getElementById('p-location').value = plan.location || '';
    document.getElementById('p-participants').value = plan.participants || '';
    document.getElementById('p-status').value = plan.status || 'Đang triển khai';
    document.getElementById('p-desc').value = plan.desc || '';
    if (editor) editor.innerHTML = getInitialRichContent(plan, plan.desc);
  } else {
    if (titleEl) titleEl.textContent = 'Thêm Kế hoạch Công đoàn sắp tới';
    document.getElementById('plan-id').value = '';
    document.getElementById('p-date').value = new Date().toISOString().slice(0, 10);
    if (editor) editor.innerHTML = '';
  }

  document.getElementById('plan-modal').classList.add('open');
  if (window.lucide) lucide.createIcons();
}

async function savePlanForm(e) {
  e.preventDefault();
  if (!requireAdminAuth('lưu kế hoạch công đoàn')) return;
  const id = document.getElementById('plan-id').value;
  const editor = document.getElementById(RICH_EDITOR_IDS.plan);
  const rawHtml = editor ? editor.innerHTML.trim() : '';
  const descVal = document.getElementById('p-desc').value.trim() || (editor ? editor.innerText.trim().slice(0, 180) : '');

  const planData = {
    id: id || 'p_' + Date.now(),
    title: document.getElementById('p-title').value.trim(),
    date: document.getElementById('p-date').value,
    category: document.getElementById('p-category').value,
    location: document.getElementById('p-location').value.trim() || 'Công ty YPMV',
    participants: document.getElementById('p-participants').value.trim() || 'Toàn thể đoàn viên',
    status: document.getElementById('p-status').value,
    desc: descVal,
    contentHtml: sanitizeRichHtml(rawHtml || `<p>${escapeHtml(descVal)}</p>`),
  };

  if (id) {
    const idx = plans.findIndex((p) => p.id === id);
    if (idx > -1) plans[idx] = planData;
    showToast(`Đã cập nhật kế hoạch: "${planData.title}"`);
  } else {
    plans.unshift(planData);
    showToast(`Đã thêm kế hoạch mới: "${planData.title}"`);
  }

  await saveAllData();
  closeModal('plan-modal');
  renderAll();
}

function editPlan(id) {
  if (!requireAdminAuth('chỉnh sửa kế hoạch')) return;
  const item = plans.find((p) => p.id === id);
  if (item) openPlanModal(item);
}

async function deletePlan(id) {
  if (!requireAdminAuth('xóa kế hoạch')) return;
  const item = plans.find((p) => p.id === id);
  if (!item) return;
  if (confirm(`Bạn có chắc muốn xóa kế hoạch "${item.title}" khỏi danh sách?`)) {
    plans = plans.filter((p) => p.id !== id);
    await saveAllData();
    renderAll();
    showToast(`Đã xóa kế hoạch "${item.title}" khỏi danh sách.`);
  }
}

// ============================================================================
// MỤC 3: CHÍNH SÁCH CÔNG ĐOÀN
// ============================================================================

function renderPolicies() {
  const container = document.getElementById('policies-container');
  container.innerHTML = policies
    .map(
      (pol) => `
      <div class="policy-card clickable" onclick="openArticleReader('policy', '${pol.id}')">
        <span class="policy-group-tag">${escapeHtml(pol.group)}</span>
        <h4>${escapeHtml(pol.title)}</h4>
        <div class="policy-amount">${escapeHtml(pol.amount)}</div>
        <p class="post-text-content">${escapeHtml(pol.desc)}</p>
        <span class="read-more-link"><i data-lucide="book-open"></i> Nhấn để xem chi tiết chính sách</span>
        ${
          currentAdmin
            ? `
          <div class="card-admin-actions" onclick="event.stopPropagation()">
            <button class="btn-card-action" onclick="editPolicy('${pol.id}')">
              <i data-lucide="pencil"></i> Chỉnh sửa
            </button>
            <button class="btn-card-action danger" onclick="deletePolicy('${pol.id}')">
              <i data-lucide="trash-2"></i> Xóa
            </button>
          </div>
        `
            : ''
        }
      </div>
    `
    )
    .join('');

  if (window.lucide) lucide.createIcons();
}

function openPolicyModal(policy = null) {
  if (!requireAdminAuth('cập nhật chính sách phúc lợi')) return;
  const form = document.getElementById('policy-form');
  form.reset();
  const titleEl = document.getElementById('policy-modal-title');
  const editor = document.getElementById(RICH_EDITOR_IDS.policy);

  if (policy) {
    if (titleEl) titleEl.textContent = 'Chỉnh sửa Chính sách / Mức phúc lợi';
    document.getElementById('policy-id').value = policy.id;
    document.getElementById('pol-title').value = policy.title || '';
    document.getElementById('pol-amount').value = policy.amount || '';
    document.getElementById('pol-group').value = policy.group || 'Hiếu - Hỷ - Thăm hỏi';
    document.getElementById('pol-desc').value = policy.desc || '';
    if (editor) editor.innerHTML = getInitialRichContent(policy, policy.desc);
  } else {
    if (titleEl) titleEl.textContent = 'Thêm Chính sách / Mức phúc lợi Công đoàn';
    document.getElementById('policy-id').value = '';
    if (editor) editor.innerHTML = '';
  }

  document.getElementById('policy-modal').classList.add('open');
  if (window.lucide) lucide.createIcons();
}

async function savePolicyForm(e) {
  e.preventDefault();
  if (!requireAdminAuth('lưu chính sách phúc lợi')) return;
  const id = document.getElementById('policy-id').value;
  const editor = document.getElementById(RICH_EDITOR_IDS.policy);
  const rawHtml = editor ? editor.innerHTML.trim() : '';
  const descVal = document.getElementById('pol-desc').value.trim();

  const polData = {
    id: id || 'pol_' + Date.now(),
    title: document.getElementById('pol-title').value.trim(),
    amount: document.getElementById('pol-amount').value.trim(),
    group: document.getElementById('pol-group').value,
    desc: descVal,
    contentHtml: sanitizeRichHtml(rawHtml || `<p>${escapeHtml(descVal)}</p>`),
  };

  if (id) {
    const idx = policies.findIndex((p) => p.id === id);
    if (idx > -1) policies[idx] = polData;
    showToast(`Đã cập nhật chính sách: "${polData.title}"`);
  } else {
    policies.unshift(polData);
    showToast(`Đã bổ sung chính sách mới: "${polData.title}"`);
  }

  await saveAllData();
  closeModal('policy-modal');
  renderAll();
}

function editPolicy(id) {
  if (!requireAdminAuth('chỉnh sửa chính sách')) return;
  const item = policies.find((p) => p.id === id);
  if (item) openPolicyModal(item);
}

async function deletePolicy(id) {
  if (!requireAdminAuth('xóa chính sách')) return;
  const item = policies.find((p) => p.id === id);
  if (!item) return;
  if (confirm(`Bạn có chắc muốn xóa chính sách "${item.title}" khỏi danh sách?`)) {
    policies = policies.filter((p) => p.id !== id);
    await saveAllData();
    renderAll();
    showToast(`Đã xóa chính sách "${item.title}" khỏi danh sách.`);
  }
}

// ============================================================================
// MỤC 4: HOẠT ĐỘNG CÔNG ĐOÀN
// ============================================================================

function renderActivities() {
  const container = document.getElementById('activities-container');
  container.innerHTML = activities
    .map(
      (act) => `
      <article class="activity-card clickable" onclick="openArticleReader('activity', '${act.id}')">
        <div class="activity-banner" style="background: ${act.gradient || 'linear-gradient(135deg, #d90429, #1e293b)'}">
          <span class="activity-tag">${escapeHtml(act.tag)}</span>
          <span class="activity-highlight">${escapeHtml(act.highlight || 'Hoạt động tiêu biểu YPMV')}</span>
        </div>
        <div class="activity-body">
          <span class="activity-date">Ngày tổ chức: ${escapeHtml(act.date)}</span>
          <h4>${escapeHtml(act.title)}</h4>
          <p class="post-text-content" style="flex: 1;">${escapeHtml(act.summary)}</p>
          <span class="read-more-link"><i data-lucide="book-open"></i> Nhấn để đọc toàn bộ bài viết (Văn bản, Ảnh & Video)</span>
          ${
            currentAdmin
              ? `
            <div class="card-admin-actions" onclick="event.stopPropagation()">
              <button class="btn-card-action" onclick="editActivity('${act.id}')">
                <i data-lucide="pencil"></i> Chỉnh sửa bài viết
              </button>
              <button class="btn-card-action danger" onclick="deleteActivity('${act.id}')">
                <i data-lucide="trash-2"></i> Xóa bài
              </button>
            </div>
          `
              : ''
          }
        </div>
      </article>
    `
    )
    .join('');

  if (window.lucide) lucide.createIcons();
}

function openActivityModal(activity = null) {
  if (!requireAdminAuth('cập nhật bài viết hoạt động công đoàn')) return;
  const form = document.getElementById('activity-form');
  form.reset();
  const titleEl = document.getElementById('activity-modal-title');
  const editor = document.getElementById(RICH_EDITOR_IDS.activity);

  if (activity) {
    if (titleEl) titleEl.textContent = 'Chỉnh sửa Bài viết Hoạt động Công đoàn';
    document.getElementById('activity-id').value = activity.id;
    document.getElementById('act-title').value = activity.title || '';
    document.getElementById('act-date').value = activity.date || '';
    document.getElementById('act-tag').value = activity.tag || 'Văn nghệ - Thể thao';
    document.getElementById('act-highlight').value = activity.highlight || '';
    document.getElementById('act-summary').value = activity.summary || '';
    if (editor) editor.innerHTML = getInitialRichContent(activity, activity.summary);
  } else {
    if (titleEl) titleEl.textContent = 'Đăng bài Hoạt động Công đoàn mới';
    document.getElementById('activity-id').value = '';
    document.getElementById('act-date').value = new Date().toISOString().slice(0, 10);
    if (editor) editor.innerHTML = '';
  }

  document.getElementById('activity-modal').classList.add('open');
  if (window.lucide) lucide.createIcons();
}

async function saveActivityForm(e) {
  e.preventDefault();
  if (!requireAdminAuth('lưu bài viết hoạt động công đoàn')) return;
  const id = document.getElementById('activity-id').value;
  const existing = id ? activities.find((a) => a.id === id) : null;
  const editor = document.getElementById(RICH_EDITOR_IDS.activity);
  const rawHtml = editor ? editor.innerHTML.trim() : '';
  const summaryVal = document.getElementById('act-summary').value.trim();

  const actData = {
    id: id || 'act_' + Date.now(),
    title: document.getElementById('act-title').value.trim(),
    date: document.getElementById('act-date').value,
    tag: document.getElementById('act-tag').value,
    highlight: document.getElementById('act-highlight').value.trim() || 'Phong trào Đoàn viên YPMV',
    summary: summaryVal,
    contentHtml: sanitizeRichHtml(rawHtml || `<p>${escapeHtml(summaryVal)}</p>`),
    gradient: existing?.gradient || 'linear-gradient(135deg, #d90429, #0f172a)',
  };

  if (id) {
    const idx = activities.findIndex((a) => a.id === id);
    if (idx > -1) activities[idx] = actData;
    showToast(`Đã cập nhật bài viết hoạt động: "${actData.title}"`);
  } else {
    activities.unshift(actData);
    showToast(`Đã đăng bài hoạt động mới: "${actData.title}"`);
  }

  await saveAllData();
  closeModal('activity-modal');
  renderAll();
}

function editActivity(id) {
  if (!requireAdminAuth('chỉnh sửa bài viết hoạt động')) return;
  const item = activities.find((a) => a.id === id);
  if (item) openActivityModal(item);
}

async function deleteActivity(id) {
  if (!requireAdminAuth('xóa bài viết hoạt động')) return;
  const item = activities.find((a) => a.id === id);
  if (!item) return;
  if (confirm(`Bạn có chắc muốn xóa bài viết hoạt động "${item.title}" khỏi danh sách?`)) {
    activities = activities.filter((a) => a.id !== id);
    await saveAllData();
    renderAll();
    showToast(`Đã xóa bài viết "${item.title}" khỏi danh sách.`);
  }
}

// ============================================================================
// MỤC 5: ĐĂNG NHẬP, CHỐNG DÒ MẬT KHẨU & QUẢN LÝ TỐI ĐA 10 TÀI KHOẢN QUẢN TRỊ
// ============================================================================

function createSignedSession(adminObj) {
  const token = hashPasswordSync(adminObj.id + ':' + adminObj.username + ':' + adminObj.passwordHash);
  return {
    id: adminObj.id,
    username: adminObj.username,
    token,
    expiresAt: Date.now() + SESSION_TIMEOUT_MS,
  };
}

function refreshSessionExpiry() {
  if (!currentAdmin || isServerMode) return;
  localStorage.setItem(STORAGE_KEYS.SESSION, JSON.stringify(createSignedSession(currentAdmin)));
}

function getLoginGuard() {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEYS.LOGIN_GUARD) || '{"attempts":0,"lockUntil":0}');
  } catch {
    return { attempts: 0, lockUntil: 0 };
  }
}

function setLoginGuard(guard) {
  localStorage.setItem(STORAGE_KEYS.LOGIN_GUARD, JSON.stringify(guard));
}

function requireAdminAuth(actionText = 'cập nhật dữ liệu') {
  if (currentAdmin) {
    if (!isServerMode) {
      const savedSession = JSON.parse(localStorage.getItem(STORAGE_KEYS.SESSION) || 'null');
      if (savedSession && savedSession.expiresAt && Date.now() < savedSession.expiresAt) {
        refreshSessionExpiry();
        return true;
      }
      currentAdmin = null;
      localStorage.removeItem(STORAGE_KEYS.SESSION);
      renderAll();
      showToast('Phiên đăng nhập quản trị đã hết hạn sau 30 phút. Vui lòng đăng nhập lại!');
      openLoginModal();
      return false;
    }
    return true;
  }
  showToast(`Vui lòng đăng nhập tài khoản Quản trị để ${actionText}!`);
  openLoginModal();
  return false;
}

function openLoginModal() {
  const form = document.getElementById('login-modal-form');
  if (form) form.reset();
  document.getElementById('login-modal')?.classList.add('open');
}

async function handleLoginSubmit(e, source = 'modal') {
  e.preventDefault();

  const userEl = document.getElementById(source === 'modal' ? 'modal-login-user' : 'inline-login-user');
  const passEl = document.getElementById(source === 'modal' ? 'modal-login-pass' : 'inline-login-pass');

  const username = (userEl?.value || '').trim();
  const password = passEl?.value || '';

  if (isServerMode) {
    try {
      const data = await apiRequest('/api/login', 'POST', { username, password });
      serverToken = data.token || '';
      localStorage.setItem(STORAGE_KEYS.SERVER_TOKEN, serverToken);
      currentAdmin = data.currentAdmin;
      members = Array.isArray(data.members) ? data.members : [];
      if (Array.isArray(data.admins)) admins = data.admins;
      welfareRequests = Array.isArray(data.welfareRequests) ? data.welfareRequests : [];
      if (passEl) passEl.value = '';
      closeModal('login-modal');
      renderAll();
      showToast(`Đăng nhập Máy chủ thành công! Xin chào ${currentAdmin.fullName} (${currentAdmin.username}).`);
    } catch (err) {
      showToast(err.message || 'Đăng nhập thất bại!');
    }
    return;
  }

  const guard = getLoginGuard();
  if (guard.lockUntil && Date.now() < guard.lockUntil) {
    const waitSec = Math.ceil((guard.lockUntil - Date.now()) / 1000);
    showToast(`Tài khoản đang tạm khóa chống dò mật khẩu! Vui lòng thử lại sau ${waitSec} giây.`);
    return;
  }

  const matched = admins.find(
    (a) =>
      a.username.toLowerCase() === username.toLowerCase() &&
      verifyPassword(password, a.passwordHash || a.password)
  );

  if (!matched) {
    const attempts = (guard.attempts || 0) + 1;
    if (attempts >= MAX_LOGIN_ATTEMPTS) {
      setLoginGuard({ attempts: 0, lockUntil: Date.now() + LOCKOUT_DURATION_MS });
      showToast(`Bạn đã nhập sai ${MAX_LOGIN_ATTEMPTS} lần liên tiếp! Tạm khóa đăng nhập trong 5 phút.`);
    } else {
      setLoginGuard({ attempts, lockUntil: 0 });
      showToast(`Sai tên đăng nhập hoặc mật khẩu! (Còn ${MAX_LOGIN_ATTEMPTS - attempts} lần thử).`);
    }
    return;
  }

  setLoginGuard({ attempts: 0, lockUntil: 0 });
  currentAdmin = matched;
  refreshSessionExpiry();
  if (passEl) passEl.value = '';
  closeModal('login-modal');
  renderAll();
  showToast(`Đăng nhập thành công! Xin chào ${matched.fullName} (${matched.username}).`);
}

async function logoutAdmin() {
  const oldName = currentAdmin?.username || '';
  if (isServerMode) {
    try {
      await apiRequest('/api/logout', 'POST');
    } catch {}
    serverToken = '';
    localStorage.removeItem(STORAGE_KEYS.SERVER_TOKEN);
    members = []; // Xóa danh sách chi tiết khỏi bộ nhớ trình duyệt khi đăng xuất
    welfareRequests = [];
  }
  currentAdmin = null;
  localStorage.removeItem(STORAGE_KEYS.SESSION);
  renderAll();
  showToast(`Đã đăng xuất tài khoản quản trị ${oldName}.`);
}

function renderAuthUI() {
  const isLogged = Boolean(currentAdmin);

  document.querySelectorAll('.admin-only').forEach((el) => {
    el.style.display = isLogged ? '' : 'none';
  });
  document.querySelectorAll('.guest-only').forEach((el) => {
    el.style.display = isLogged ? 'none' : '';
  });

  const badgeEl = document.getElementById('auth-badge-text');
  const btnLogin = document.getElementById('btn-top-login');

  if (badgeEl) {
    if (isLogged) {
      badgeEl.style.display = '';
      badgeEl.className = 'auth-badge logged';
      badgeEl.innerHTML = `<i data-lucide="shield-check"></i> Quản trị: ${escapeHtml(currentAdmin.username)}`;
    } else {
      badgeEl.style.display = 'none';
      badgeEl.innerHTML = '';
    }
  }
  if (btnLogin) {
    btnLogin.style.display = isLogged ? 'none' : '';
  }

  const navAdminCount = document.getElementById('nav-admin-count');
  if (navAdminCount) navAdminCount.textContent = `${admins.length}/${MAX_ADMIN_ACCOUNTS}`;

  const topAdminCount = document.getElementById('top-admin-count');
  if (topAdminCount) topAdminCount.textContent = admins.length;
}

const APPROVAL_ROLE_LABELS = {
  requester: 'Người yêu cầu',
  checker1: 'Người kiểm tra 1 (PCT Hoạt động)',
  checker2: 'Người kiểm tra 2 (PCT Tài chính)',
  approver: 'Người phê duyệt (Chủ tịch)',
  accountant: 'Kế toán xác nhận',
};

function getApprovalRoleBadgeHtml(approvalRole) {
  const label = APPROVAL_ROLE_LABELS[approvalRole] || APPROVAL_ROLE_LABELS.requester;
  return `<span class="approval-role-pill role-${escapeHtml(approvalRole || 'requester')}">${escapeHtml(label)}</span>`;
}

function renderAdminsSection() {
  const loginBox = document.getElementById('admin-login-box-view');
  const loggedBox = document.getElementById('admin-logged-in-view');

  if (loginBox && loggedBox) {
    if (currentAdmin) {
      loginBox.style.display = 'none';
      loggedBox.style.display = 'block';
      document.getElementById('current-admin-fullname').textContent = currentAdmin.fullName;
      document.getElementById('current-admin-username').textContent = currentAdmin.username;
      const roleText = currentAdmin.role || 'Ban Chấp hành';
      const appRoleLabel = APPROVAL_ROLE_LABELS[currentAdmin.approvalRole] || 'Người yêu cầu';
      document.getElementById('current-admin-role').textContent = `${roleText} • ${appRoleLabel}`;
    } else {
      loginBox.style.display = 'block';
      loggedBox.style.display = 'none';
    }
  }

  const slotCounter = document.getElementById('admin-slot-counter');
  if (slotCounter) slotCounter.textContent = `${admins.length}/${MAX_ADMIN_ACCOUNTS}`;

  const limitBadge = document.getElementById('admin-limit-badge');
  if (limitBadge) {
    const remaining = MAX_ADMIN_ACCOUNTS - admins.length;
    if (remaining <= 0) {
      limitBadge.className = 'limit-pill full';
      limitBadge.textContent = `Đã đạt giới hạn tối đa ${MAX_ADMIN_ACCOUNTS}/${MAX_ADMIN_ACCOUNTS} tài khoản`;
    } else {
      limitBadge.className = 'limit-pill';
      limitBadge.textContent = `Còn có thể tạo thêm ${remaining}/${MAX_ADMIN_ACCOUNTS} tài khoản`;
    }
  }

  const tbody = document.getElementById('admins-tbody');
  if (!tbody) return;

  tbody.innerHTML = admins
    .map((adm, idx) => {
      const isRoot = adm.id === 'adm_root' || adm.isPrimary;
      let actionHtml = `<span class="text-muted" style="font-size:12px;">Cần đăng nhập</span>`;

      if (currentAdmin) {
        actionHtml = `
          <div class="row-actions">
            <button class="btn-action" onclick="editAdminAccount('${adm.id}')" title="Sửa Tên, Mật khẩu, Chức vụ">
              <i data-lucide="pencil"></i>
            </button>
            ${
              isRoot
                ? `<span class="status-pill status-bch" title="Tài khoản quản trị chính">TK Chính</span>`
                : `<button class="btn-action" onclick="deleteAdminAccount('${adm.id}')" title="Xóa tài khoản quản trị">
                    <i data-lucide="trash-2"></i>
                  </button>`
            }
          </div>
        `;
      }

      return `
        <tr>
          <td>${idx + 1}</td>
          <td><span class="emp-code">${escapeHtml(adm.username)}</span></td>
          <td><strong>${escapeHtml(adm.fullName)}</strong></td>
          <td>
            <div>${escapeHtml(adm.role || 'Ủy viên BCH')}</div>
            <div style="margin-top:4px;">${getApprovalRoleBadgeHtml(adm.approvalRole)}</div>
          </td>
          <td>${escapeHtml(adm.createdAt || '-')}</td>
          <td style="text-align: right;">${actionHtml}</td>
        </tr>
      `;
    })
    .join('');

  if (window.lucide) lucide.createIcons();
}

function openAdminAccountModal(adminItem = null) {
  if (!requireAdminAuth('quản lý tài khoản quản trị')) return;

  const form = document.getElementById('admin-account-form');
  form?.reset();
  const passInput = document.getElementById('adm-password');
  const passLabel = document.getElementById('adm-password-label');

  if (adminItem) {
    document.getElementById('admin-modal-title').textContent = `Chỉnh sửa Tài khoản Quản trị (${adminItem.username})`;
    document.getElementById('adm-id').value = adminItem.id;
    document.getElementById('adm-username').value = adminItem.username || '';
    if (passInput) {
      passInput.value = '';
      passInput.required = false;
      passInput.placeholder = 'Bỏ trống nếu giữ nguyên mật khẩu cũ';
    }
    if (passLabel) {
      passLabel.innerHTML = 'Mật khẩu mới <span class="text-muted" style="font-weight:400;">(để trống nếu không đổi)</span>';
    }
    document.getElementById('adm-fullname').value = adminItem.fullName || '';
    document.getElementById('adm-role').value = adminItem.role || '';
    const appRoleSel = document.getElementById('adm-approval-role');
    if (appRoleSel) appRoleSel.value = adminItem.approvalRole || 'requester';
  } else {
    if (admins.length >= MAX_ADMIN_ACCOUNTS) {
      showToast(`Hệ thống chỉ cho phép tạo tối đa ${MAX_ADMIN_ACCOUNTS} tài khoản quản trị!`);
      return;
    }
    document.getElementById('admin-modal-title').textContent = `Tạo Tài khoản Quản trị (${admins.length + 1}/${MAX_ADMIN_ACCOUNTS})`;
    document.getElementById('adm-id').value = '';
    if (passInput) {
      passInput.value = '';
      passInput.required = true;
      passInput.placeholder = 'Nhập mật khẩu (tối thiểu 6 ký tự)';
    }
    if (passLabel) {
      passLabel.innerHTML = 'Mật khẩu <span class="req">*</span>';
    }
  }

  document.getElementById('admin-account-modal')?.classList.add('open');
}

function editAdminAccount(id) {
  if (!requireAdminAuth('chỉnh sửa tài khoản quản trị')) return;
  const target = admins.find((a) => a.id === id);
  if (target) openAdminAccountModal(target);
}

function editCurrentAdminAccount() {
  if (!requireAdminAuth('chỉnh sửa tài khoản của bạn')) return;
  openAdminAccountModal(currentAdmin);
}

async function saveAdminAccountForm(e) {
  e.preventDefault();
  if (!requireAdminAuth('lưu thông tin tài khoản quản trị')) return;

  const editId = document.getElementById('adm-id').value;
  const username = document.getElementById('adm-username').value.trim();
  const password = document.getElementById('adm-password').value;
  const fullName = document.getElementById('adm-fullname').value.trim();
  const role = document.getElementById('adm-role').value.trim() || 'Ủy viên BCH Công đoàn';
  const approvalRole = document.getElementById('adm-approval-role')?.value || 'requester';

  if (isServerMode) {
    try {
      const res = await apiRequest('/api/admins/save', 'POST', {
        id: editId,
        username,
        password,
        fullName,
        role,
        approvalRole,
      });
      admins = res.admins || admins;
      if (res.currentAdmin) currentAdmin = res.currentAdmin;
      closeModal('admin-account-modal');
      renderAll();
      showToast(`Đã lưu thông tin tài khoản quản trị "${username}" lên Máy chủ!`);
    } catch (err) {
      showToast(err.message || 'Không thể lưu tài khoản quản trị!');
    }
    return;
  }

  if (!/^[a-zA-Z0-9_.-]+$/.test(username)) {
    showToast('Tên đăng nhập chỉ được chứa chữ cái không dấu, số và ký tự gạch dưới!');
    return;
  }

  const duplicate = admins.some(
    (a) => a.id !== editId && a.username.toLowerCase() === username.toLowerCase()
  );
  if (duplicate) {
    showToast(`Tên đăng nhập "${username}" đã được sử dụng bởi tài khoản khác!`);
    return;
  }

  if (editId) {
    const idx = admins.findIndex((a) => a.id === editId);
    if (idx > -1) {
      if (password && password.length < 6) {
        showToast('Mật khẩu mới phải có ít nhất 6 ký tự!');
        return;
      }
      const updated = {
        ...admins[idx],
        username,
        passwordHash: password ? hashPasswordSync(password) : admins[idx].passwordHash,
        fullName,
        role,
        approvalRole,
      };
      delete updated.password;
      admins[idx] = updated;

      if (currentAdmin && currentAdmin.id === editId) {
        currentAdmin = updated;
        refreshSessionExpiry();
      }
      await saveAllData();
      closeModal('admin-account-modal');
      renderAll();
      showToast(`Đã cập nhật thông tin tài khoản quản trị "${username}" (${fullName}).`);
      return;
    }
  }

  if (!password || password.length < 6) {
    showToast('Mật khẩu phải có ít nhất 6 ký tự!');
    return;
  }

  if (admins.length >= MAX_ADMIN_ACCOUNTS) {
    showToast(`Đã đạt giới hạn tối đa ${MAX_ADMIN_ACCOUNTS} tài khoản quản trị!`);
    closeModal('admin-account-modal');
    return;
  }

  admins.push({
    id: 'adm_' + Date.now(),
    username,
    passwordHash: hashPasswordSync(password),
    fullName,
    role,
    approvalRole,
    createdAt: new Date().toISOString().slice(0, 10),
    isPrimary: false,
  });

  await saveAllData();
  closeModal('admin-account-modal');
  renderAll();
  showToast(`Đã tạo tài khoản quản trị "${username}" (${admins.length}/${MAX_ADMIN_ACCOUNTS} tài khoản).`);
}

async function deleteAdminAccount(id) {
  if (!requireAdminAuth('xóa tài khoản quản trị')) return;

  const target = admins.find((a) => a.id === id);
  if (!target) return;

  if (target.id === 'adm_root' || target.isPrimary) {
    showToast('Không thể xóa tài khoản quản trị chính! Bạn có thể bấm nút Sửa (cây bút) để đổi tên đăng nhập, họ tên, mật khẩu hoặc chức vụ.');
    return;
  }

  if (!confirm(`Bạn có chắc muốn xóa tài khoản quản trị "${target.username}" (${target.fullName})?`)) {
    return;
  }

  if (isServerMode) {
    try {
      const res = await apiRequest('/api/admins/delete', 'POST', { id });
      admins = res.admins || admins;
      renderAll();
      showToast(`Đã xóa tài khoản quản trị "${target.username}" trên Máy chủ.`);
    } catch (err) {
      showToast(err.message || 'Lỗi xóa tài khoản!');
    }
    return;
  }

  admins = admins.filter((a) => a.id !== id);
  if (currentAdmin && currentAdmin.id === id) {
    currentAdmin = null;
    localStorage.removeItem(STORAGE_KEYS.SESSION);
  }
  await saveAllData();
  renderAll();
  showToast(`Đã xóa tài khoản quản trị "${target.username}". Hiện có ${admins.length}/${MAX_ADMIN_ACCOUNTS} tài khoản.`);
}

// ============================================================================
// 5.2 QUY TRÌNH TẠO & DUYỆT ĐƠN PHÚC LỢI 6 BƯỚC
// ============================================================================

const WELFARE_STATUS_META = {
  pending_checker1: { label: 'Chưa hoàn thành • Chờ Kiểm tra 1 (PCT HĐ)', cls: 'pending' },
  pending_checker2: { label: 'Chưa hoàn thành • Chờ Kiểm tra 2 (PCT TC)', cls: 'pending' },
  pending_approver: { label: 'Chưa hoàn thành • Chờ Phê duyệt (Chủ tịch)', cls: 'pending' },
  pending_accountant: { label: 'Chưa hoàn thành • Chờ Kế toán xác nhận', cls: 'pending' },
  pending_confirm: { label: 'Chưa hoàn thành • Chờ Người YC xác nhận', cls: 'pending' },
  completed: { label: 'Đã hoàn thành', cls: 'completed' },
  cancelled: { label: 'Đã hủy đơn', cls: 'cancelled' },
  rejected: { label: 'Không đồng ý / Từ chối', cls: 'rejected' },
};

function openWelfareModal() {
  if (!requireAdminAuth('tạo đơn yêu cầu phúc lợi')) return;
  document.getElementById('welfare-create-form')?.reset();
  document.getElementById('welfare-create-modal')?.classList.add('open');
}

async function saveWelfareRequestForm(e) {
  e.preventDefault();
  if (!requireAdminAuth('gửi đơn yêu cầu phúc lợi')) return;

  const title = document.getElementById('w-title').value.trim();
  const policyGroup = document.getElementById('w-policy-group').value;
  const amount = document.getElementById('w-amount').value.trim();
  const beneficiary = document.getElementById('w-beneficiary').value.trim();
  const reason = document.getElementById('w-reason').value.trim();

  if (!title || !amount || !beneficiary) {
    showToast('Vui lòng điền đầy đủ Tiêu đề, Số tiền và Đoàn viên thụ hưởng!');
    return;
  }

  if (isServerMode) {
    try {
      const res = await apiRequest('/api/welfare/create', 'POST', {
        title,
        policyGroup,
        beneficiary,
        amount,
        reason,
      });
      welfareRequests = res.welfareRequests || welfareRequests;
      closeModal('welfare-create-modal');
      renderWelfareRequests();
      showToast('Đã tạo đơn phúc lợi và chuyển sang Bước 2 (Người kiểm tra 1)!');
    } catch (err) {
      showToast(err.message || 'Không thể tạo đơn phúc lợi!');
    }
    return;
  }

  const newReq = {
    id: 'WLR-' + new Date().toISOString().slice(2, 10).replace(/-/g, '') + '-' + Math.floor(100 + Math.random() * 900),
    title,
    policyGroup,
    beneficiary,
    amount,
    reason,
    requesterId: currentAdmin.id,
    requesterUsername: currentAdmin.username,
    requesterName: currentAdmin.fullName,
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
  welfareRequests.unshift(newReq);
  await saveAllData();
  closeModal('welfare-create-modal');
  renderWelfareRequests();
  showToast('Đã tạo đơn phúc lợi (Offline) và chuyển sang Bước 2!');
}

function setWelfareFilter(filter, btnEl) {
  selectedWelfareFilter = filter;
  document.querySelectorAll('.welfare-filter-chips .chip').forEach((btn) => {
    btn.classList.toggle('active', btn === btnEl);
  });
  renderWelfareRequests();
}

function isMyTurnForWelfare(reqItem) {
  if (!currentAdmin) return false;
  const role = currentAdmin.approvalRole || 'requester';
  if (reqItem.status === 'pending_checker1') return role === 'checker1';
  if (reqItem.status === 'pending_checker2') return role === 'checker2';
  if (reqItem.status === 'pending_approver') return role === 'approver';
  if (reqItem.status === 'pending_accountant') return role === 'accountant';
  if (reqItem.status === 'pending_confirm') {
    return (
      reqItem.requesterId === currentAdmin.id ||
      (reqItem.requesterUsername && reqItem.requesterUsername.toLowerCase() === currentAdmin.username.toLowerCase())
    );
  }
  return false;
}

function renderWelfareRequests() {
  const container = document.getElementById('welfare-requests-container');
  if (!container) return;

  if (!currentAdmin) {
    container.innerHTML = '';
    return;
  }

  const setCount = (id, val) => {
    const el = document.getElementById(id);
    if (el) el.textContent = String(val);
  };
  setCount('w-count-all', welfareRequests.length);
  setCount('w-count-my', welfareRequests.filter((w) => isMyTurnForWelfare(w)).length);
  setCount('w-count-progress', welfareRequests.filter((w) => w.status && w.status.startsWith('pending_')).length);
  setCount('w-count-done', welfareRequests.filter((w) => w.status === 'completed').length);
  setCount('w-count-cancelled', welfareRequests.filter((w) => w.status === 'cancelled').length);
  setCount('w-count-reject', welfareRequests.filter((w) => w.status === 'rejected').length);

  let filtered = welfareRequests;
  if (selectedWelfareFilter === 'MY_ACTION') {
    filtered = welfareRequests.filter((w) => isMyTurnForWelfare(w));
  } else if (selectedWelfareFilter === 'IN_PROGRESS') {
    filtered = welfareRequests.filter((w) => w.status && w.status.startsWith('pending_'));
  } else if (selectedWelfareFilter === 'COMPLETED') {
    filtered = welfareRequests.filter((w) => w.status === 'completed');
  } else if (selectedWelfareFilter === 'CANCELLED') {
    filtered = welfareRequests.filter((w) => w.status === 'cancelled');
  } else if (selectedWelfareFilter === 'REJECTED') {
    filtered = welfareRequests.filter((w) => w.status === 'rejected');
  }

  if (filtered.length === 0) {
    container.innerHTML = `
      <div class="empty-state" style="padding:28px 16px;text-align:center;color:var(--text-muted);background:#f8fafc;border-radius:10px;border:1px dashed var(--border);">
        Chưa có đơn yêu cầu phúc lợi nào trong mục này. Nhấn <strong>"Tạo đơn phúc lợi"</strong> để khởi tạo yêu cầu mới.
      </div>
    `;
    return;
  }

  container.innerHTML = filtered
    .map((w) => {
      const myTurn = isMyTurnForWelfare(w);
      const statusMeta = WELFARE_STATUS_META[w.status] || { label: w.status, cls: 'pending' };
      const createdDate = w.createdAt ? new Date(w.createdAt).toLocaleString('vi-VN') : '';
      const steps = w.steps || {};

      const stepDefs = [
        {
          name: '1. Người yêu cầu',
          state: 'done',
          statusText: 'Đã gửi đơn',
          by: w.requesterName || w.requesterUsername,
          note: '',
        },
        {
          name: '2. Kiểm tra 1 (PCT HĐ)',
          key: 'checker1',
          pendingStatus: 'pending_checker1',
        },
        {
          name: '3. Kiểm tra 2 (PCT TC)',
          key: 'checker2',
          pendingStatus: 'pending_checker2',
        },
        {
          name: '4. Phê duyệt (Chủ tịch)',
          key: 'approver',
          pendingStatus: 'pending_approver',
        },
        {
          name: '5. Kế toán xác nhận',
          key: 'accountant',
          pendingStatus: 'pending_accountant',
        },
        {
          name: '6. Người YC xác nhận',
          key: 'requesterConfirm',
          pendingStatus: 'pending_confirm',
        },
      ];

      const stepsHtml = stepDefs
        .map((st, idx) => {
          if (idx === 0) {
            return `
              <div class="w-step-box done">
                <div class="w-step-name">${st.name}</div>
                <div class="w-step-status">✔ Đã gửi đơn</div>
                <div class="w-step-by">${escapeHtml(st.by)}</div>
              </div>
            `;
          }
          const stData = steps[st.key] || { decision: 'pending' };
          let boxCls = '';
          let statusLabel = 'Chờ tới lượt';
          if (stData.decision === 'approved') {
            boxCls = 'done';
            statusLabel = '✔ Đồng ý';
          } else if (stData.decision === 'confirmed') {
            boxCls = 'done';
            statusLabel = '✔ Đã xác nhận hoàn thành';
          } else if (stData.decision === 'cancelled') {
            boxCls = 'cancelled';
            statusLabel = '✖ Đã hủy đơn';
          } else if (stData.decision === 'rejected') {
            boxCls = 'rejected';
            statusLabel = '✖ Không đồng ý';
          } else if (w.status === st.pendingStatus) {
            boxCls = 'active';
            statusLabel = '⏳ Đang chờ xử lý';
          }
          const byText = stData.byName ? escapeHtml(stData.byName) : '';
          const noteText = stData.note ? `<div class="w-step-note"><strong>Chú thích:</strong> ${escapeHtml(stData.note)}</div>` : '';
          return `
            <div class="w-step-box ${boxCls}">
              <div class="w-step-name">${st.name}</div>
              <div class="w-step-status">${statusLabel}</div>
              ${byText ? `<div class="w-step-by">${byText}</div>` : ''}
              ${noteText}
            </div>
          `;
        })
        .join('');

      const isOwner =
        w.requesterId === currentAdmin.id ||
        (w.requesterUsername && w.requesterUsername.toLowerCase() === currentAdmin.username.toLowerCase());
      const isPending = Boolean(w.status && w.status.startsWith('pending_'));

      let actionBarHtml = '';
      if (myTurn && w.status === 'pending_confirm') {
        actionBarHtml = `
          <div class="welfare-action-bar">
            <span>🔔 <strong>Đến lượt bạn (${escapeHtml(currentAdmin.fullName)}):</strong> Tất cả các cấp đã đồng ý. Vui lòng xác nhận hoàn thành hoặc hủy đơn (kèm chú thích):</span>
            <div class="welfare-action-btns">
              <button class="btn-approve" onclick="handleWelfareAction('${w.id}', 'confirm')">✔ Xác nhận đã hoàn thành</button>
              <button class="btn-cancel-order" onclick="handleWelfareAction('${w.id}', 'cancel')">✖ Hủy đơn (có chú thích)</button>
            </div>
          </div>
        `;
      } else if (myTurn || (isOwner && isPending)) {
        const approveBtns = myTurn
          ? `
              <button class="btn-approve" onclick="handleWelfareAction('${w.id}', 'approve')">✔ Đồng ý</button>
              <button class="btn-reject" onclick="handleWelfareAction('${w.id}', 'reject')">✖ Không đồng ý</button>
            `
          : '';
        const cancelBtn =
          isOwner && isPending
            ? `<button class="btn-cancel-order" onclick="handleWelfareAction('${w.id}', 'cancel')">✖ Hủy đơn (có chú thích)</button>`
            : '';
        const promptLabel = myTurn
          ? `🔔 <strong>Đến lượt bạn duyệt (${escapeHtml(APPROVAL_ROLE_LABELS[currentAdmin.approvalRole] || '')}):</strong>`
          : `📝 <strong>Đơn của bạn đang chờ duyệt:</strong> Bạn có thể hủy đơn nếu không còn nhu cầu (sẽ lưu lại lịch sử kèm chú thích).`;
        actionBarHtml = `
          <div class="welfare-action-bar">
            <span>${promptLabel}</span>
            <div class="welfare-action-btns">
              ${approveBtns}
              ${cancelBtn}
            </div>
          </div>
        `;
      }

      const canDelete = currentAdmin.id === 'adm_root' || currentAdmin.isPrimary;

      return `
        <div class="welfare-card status-${escapeHtml(statusMeta.cls)} ${myTurn ? 'is-my-turn' : ''}">
          <div class="welfare-card-top">
            <div>
              <div class="welfare-card-title">${escapeHtml(w.title)}</div>
              <div class="welfare-meta-row">
                <span><strong>Mã đơn:</strong> ${escapeHtml(w.id)}</span>
                <span><strong>Nhóm:</strong> ${escapeHtml(w.policyGroup || '-')}</span>
                <span><strong>Thụ hưởng:</strong> ${escapeHtml(w.beneficiary)}</span>
                <span><strong>Số tiền:</strong> <strong style="color:var(--yamaha-red);">${escapeHtml(w.amount)}</strong></span>
                <span><strong>Ngày tạo:</strong> ${escapeHtml(createdDate)}</span>
              </div>
              ${w.reason ? `<div style="font-size:12.5px;color:var(--text-muted);margin-top:6px;"><strong>Lý do:</strong> ${escapeHtml(w.reason)}</div>` : ''}
            </div>
            <div style="display:flex;align-items:center;gap:8px;flex-shrink:0;">
              <span class="status-pill status-${escapeHtml(statusMeta.cls)}">${escapeHtml(statusMeta.label)}</span>
              ${canDelete ? `<button class="btn-action" onclick="deleteWelfareRequest('${w.id}')" title="Xóa vĩnh viễn đơn này (chỉ TK Chính)"><i data-lucide="trash-2"></i></button>` : ''}
            </div>
          </div>
          <div class="welfare-steps-bar">${stepsHtml}</div>
          ${actionBarHtml}
        </div>
      `;
    })
    .join('');

  if (window.lucide) lucide.createIcons();
}

async function handleWelfareAction(id, decision) {
  if (!requireAdminAuth('duyệt đơn phúc lợi')) return;
  const actionLabel =
    decision === 'approve'
      ? 'ĐỒNG Ý'
      : decision === 'reject'
      ? 'KHÔNG ĐỒNG Ý (từ chối đơn)'
      : decision === 'cancel'
      ? 'HỦY ĐƠN'
      : 'XÁC NHẬN ĐÃ HOÀN THÀNH';

  const promptTitle =
    decision === 'cancel'
      ? 'Nhập chú thích / lý do HỦY ĐƠN (bắt buộc, sẽ hiển thị ở phần xác nhận):'
      : `Nhập ghi chú cho quyết định "${actionLabel}" (có thể bỏ trống):`;

  const rawNote = window.prompt(promptTitle, '');
  if (rawNote === null) return;
  const note = rawNote.trim();

  if (decision === 'cancel' && !note) {
    showToast('Vui lòng nhập chú thích / lý do hủy đơn!');
    return;
  }

  if (isServerMode) {
    try {
      const res = await apiRequest('/api/welfare/action', 'POST', { id, decision, note });
      welfareRequests = res.welfareRequests || welfareRequests;
      renderWelfareRequests();
      showToast(`Đã cập nhật trạng thái đơn ${id}: ${actionLabel}!`);
    } catch (err) {
      showToast(err.message || 'Không thể thực hiện thao tác duyệt!');
    }
    return;
  }

  const reqItem = welfareRequests.find((w) => w.id === id);
  if (!reqItem) return;
  const userRole = currentAdmin.approvalRole || 'requester';
  const nowStr = new Date().toISOString();
  const isOwner =
    reqItem.requesterId === currentAdmin.id ||
    (reqItem.requesterUsername && reqItem.requesterUsername.toLowerCase() === currentAdmin.username.toLowerCase());

  if (decision === 'cancel') {
    if (!isOwner) {
      showToast('Chỉ người tạo đơn mới được quyền hủy đơn này!');
      return;
    }
    if (!reqItem.status || !reqItem.status.startsWith('pending_')) {
      showToast('Chỉ có thể hủy đơn khi đơn chưa hoàn thành!');
      return;
    }
    reqItem.steps.requesterConfirm = {
      decision: 'cancelled',
      byName: currentAdmin.fullName,
      byUsername: currentAdmin.username,
      note,
      at: nowStr,
    };
    reqItem.status = 'cancelled';
  } else if (reqItem.status === 'pending_confirm') {
    if (!isOwner) {
      showToast('Chỉ người yêu cầu tạo đơn mới được xác nhận hoàn thành!');
      return;
    }
    reqItem.steps.requesterConfirm = {
      decision: 'confirmed',
      byName: currentAdmin.fullName,
      byUsername: currentAdmin.username,
      note: note || 'Đã xác nhận hoàn thành',
      at: nowStr,
    };
    reqItem.status = 'completed';
  } else {
    const stepMap = {
      pending_checker1: { key: 'checker1', role: 'checker1', next: 'pending_checker2' },
      pending_checker2: { key: 'checker2', role: 'checker2', next: 'pending_approver' },
      pending_approver: { key: 'approver', role: 'approver', next: 'pending_accountant' },
      pending_accountant: { key: 'accountant', role: 'accountant', next: 'pending_confirm' },
    };
    const rule = stepMap[reqItem.status];
    if (!rule || userRole !== rule.role) {
      showToast('Bạn không có quyền xử lý bước duyệt hiện tại của đơn này!');
      return;
    }
    reqItem.steps[rule.key] = {
      decision: decision === 'approve' ? 'approved' : 'rejected',
      byName: currentAdmin.fullName,
      byUsername: currentAdmin.username,
      note,
      at: nowStr,
    };
    if (decision === 'reject') {
      reqItem.status = 'rejected';
      reqItem.rejectedStep = rule.key;
    } else {
      reqItem.status = rule.next;
    }
  }

  await saveAllData();
  renderWelfareRequests();
  showToast(`Đã cập nhật đơn ${id}: ${actionLabel}!`);
}

async function deleteWelfareRequest(id) {
  if (!requireAdminAuth('xóa đơn phúc lợi')) return;
  if (!confirm(`Bạn có chắc chắn muốn xóa đơn phúc lợi "${id}"?`)) return;

  if (isServerMode) {
    try {
      const res = await apiRequest('/api/welfare/delete', 'POST', { id });
      welfareRequests = res.welfareRequests || welfareRequests;
      renderWelfareRequests();
      showToast(`Đã xóa đơn phúc lợi ${id}.`);
    } catch (err) {
      showToast(err.message || 'Không thể xóa đơn phúc lợi!');
    }
    return;
  }

  welfareRequests = welfareRequests.filter((w) => w.id !== id);
  await saveAllData();
  renderWelfareRequests();
  showToast(`Đã xóa đơn phúc lợi ${id}.`);
}

function openWelfareMatrixModal() {
  const tbody = document.getElementById('welfare-matrix-tbody');
  if (tbody) {
    tbody.innerHTML = admins
      .map((adm, idx) => {
        const r = adm.approvalRole || 'requester';
        return `
          <tr>
            <td>${idx + 1}</td>
            <td><strong>${escapeHtml(adm.fullName)}</strong><br><span class="text-muted" style="font-size:11.5px;">@${escapeHtml(adm.username)}</span></td>
            <td style="text-align:center;">✔</td>
            <td style="text-align:center;">${r === 'checker1' ? '✅ <strong>Đ/c Phí Văn Mạnh</strong>' : '—'}</td>
            <td style="text-align:center;">${r === 'checker2' ? '✅ <strong>Đ/c Nguyễn Văn Hợp</strong>' : '—'}</td>
            <td style="text-align:center;">${r === 'approver' ? '✅ <strong>Đ/c Nguyễn Huy Sáng</strong>' : '—'}</td>
            <td style="text-align:center;">${r === 'accountant' ? '✅ <strong>Kế toán CĐ</strong>' : '—'}</td>
            <td style="text-align:center;">✔ (Chính chủ đơn)</td>
          </tr>
        `;
      })
      .join('');
  }
  document.getElementById('welfare-matrix-modal')?.classList.add('open');
}

// ============================================================================
// HELPERS
// ============================================================================

function closeModal(modalId) {
  document.getElementById(modalId)?.classList.remove('open');
}

function showToast(message) {
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  toast.className = 'toast';
  toast.textContent = message;
  container.appendChild(toast);
  setTimeout(() => {
    toast.remove();
  }, 3800);
}

function escapeHtml(str) {
  return String(str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

Object.assign(window, {
  switchTab,
  closeMobileSidebar,
  selectDepartment,
  renderMembersTable,
  openMemberModal,
  onMemberSheetSelectChange,
  saveMemberForm,
  editMember,
  deleteMember,
  openAddDeptModal,
  resetDefaultMembers,
  exportMembersToExcel,
  downloadExcelTemplate,
  execRichCmd,
  insertMediaFilesIntoEditor,
  promptMediaUrlIntoEditor,
  openArticleReader,
  setPlanFilter,
  openPlanModal,
  savePlanForm,
  editPlan,
  deletePlan,
  openPolicyModal,
  savePolicyForm,
  editPolicy,
  deletePolicy,
  openActivityModal,
  saveActivityForm,
  editActivity,
  deleteActivity,
  openLoginModal,
  handleLoginSubmit,
  logoutAdmin,
  openAdminAccountModal,
  editAdminAccount,
  editCurrentAdminAccount,
  saveAdminAccountForm,
  deleteAdminAccount,
  openWelfareModal,
  saveWelfareRequestForm,
  setWelfareFilter,
  handleWelfareAction,
  deleteWelfareRequest,
  openWelfareMatrixModal,
  closeModal,
});
})();

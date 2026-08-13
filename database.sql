PRAGMA foreign_keys = ON;

-- 1. BẢNG GỐC: TECHNIQUE
CREATE TABLE technique (
    technique_id VARCHAR(20) PRIMARY KEY,
    technique_name TEXT NOT NULL,
    subtechnique_count INTEGER DEFAULT 0,
    description TEXT,
    source_note TEXT
);

-- 2. BẢNG GỐC: EVENT LOG (Tham số cấu hình hệ thống A và S)
CREATE TABLE event_log (
    event_id VARCHAR(20) PRIMARY KEY,
    event_name TEXT NOT NULL,
    description TEXT,
    audit_score REAL NOT NULL,    -- Tham số A (1.0, 2.0)
    sensor_score REAL NOT NULL    -- Tham số S (1.0, 2.5)
);

-- 3. BẢNG TỔNG QUÁT HÓA: DETECTION FILTER (Thay thế cho access_mask)
-- Lưu trữ mọi điều kiện lọc đặc hiệu: Access Mask, Logon Type, Script Text, Template Name...
CREATE TABLE detection_filter (
    filter_id VARCHAR(30) PRIMARY KEY,
    filter_field TEXT NOT NULL,   -- Tên trường trong log (vd: winlog.logon.type, winlog.event_data.AccessMask)
    filter_value TEXT NOT NULL,   -- Giá trị cụ thể (vd: 10, 0x40000, crypto::certificates)
    description TEXT
);

-- 4. BẢNG GỐC: PRIVILEGE (Ánh xạ tên Cạnh trong BloodHound)
CREATE TABLE privilege (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    privilege_name TEXT NOT NULL UNIQUE
);

-- 5. BẢNG LIÊN KẾT/PHÁT HIỆN: TECHNIQUE_DETECTION (Nơi định nghĩa V dựa trên Event + Filter)
CREATE TABLE technique_detection (
    technique_id VARCHAR(20),
    event_id VARCHAR(20),
    filter_id VARCHAR(30),
    fidelity_score REAL NOT NULL, -- Tham số V (1.0, 2.0, 4.0) nằm ở đây
    PRIMARY KEY (technique_id, event_id, filter_id),
    FOREIGN KEY (technique_id) REFERENCES technique(technique_id) ON DELETE CASCADE,
    FOREIGN KEY (event_id) REFERENCES event_log(event_id) ON DELETE CASCADE,
    FOREIGN KEY (filter_id) REFERENCES detection_filter(filter_id) ON DELETE CASCADE
);

-- 6. BẢNG LIÊN KẾT: PRIVILEGE - TECHNIQUE
CREATE TABLE privilege_technique (
    privilege_id INTEGER,
    technique_id VARCHAR(20),
    PRIMARY KEY (privilege_id, technique_id),
    FOREIGN KEY (privilege_id) REFERENCES privilege(id) ON DELETE CASCADE,
    FOREIGN KEY (technique_id) REFERENCES technique(technique_id) ON DELETE CASCADE
);

-- 7. BẢNG QUẢN LÝ PHIÊN BẢN (METADATA)
CREATE TABLE IF NOT EXISTS metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
INSERT OR IGNORE INTO metadata (key, value) VALUES ('db_version', '1');














INSERT INTO privilege (privilege_name) VALUES 
('ForceChangePassword'), ('CanRDP'), ('AddMember'), ('GenericAll'),
('AllowedToAct'), ('HasSIDHistory'), ('GenericWrite'), ('WriteDacl'), 
('WriteOwner'), ('WriteSPN'), ('ReadLAPSPassword'), ('ReadGMSAPassword'), 
('CanPSRemote'), ('ExecuteDCOM'), ('AddSelf'), ('WriteAccountRestrictions'), 
('AddAllowedToAct'), ('AllowedToDelegate'), ('AbuseTGTDelegation'), 
('SpoofSIDHistory'), ('DumpSMSAPassword'), ('AdminTo'), ('AllExtendedRights'), 
('Owns'), ('SQLAdmin'), ('AddKeyCredentialLink'), ('WriteGPLink'), 
('RemoteInteractiveLogonRight'), ('HasSession'), ('DCSync'), ('CoerceToTGT'),
('ADCSESC1'), ('ADCSESC3'), ('ADCSESC4'), ('ADCSESC6a'), ('ADCSESC6b'), 
('ADCSESC9a'), ('ADCSESC9b'), ('ADCSESC10a'), ('ADCSESC10b'), ('ADCSESC13'),
-- Vá bug: 4 loại cạnh cấu trúc AD sau đây hợp lệ theo data_cleaner.is_valid_edge()
-- nhưng trước đây thiếu trong bảng privilege, luôn nhận cost = null khi enrich.
('MemberOf'), ('Contains'), ('GPLink'), ('DCFor');




INSERT INTO technique (technique_id, technique_name, subtechnique_count, description, source_note) VALUES
('T1098', 'Account Manipulation', 0, 'Sửa đổi trực tiếp thuộc tính đối tượng AD.', 'DACL/ACL Abuse'),
('T1021.001', 'Remote Services: Remote Desktop Protocol', 1, 'Đăng nhập từ xa qua RDP.', 'RDP Interactive'),
('T1021.003', 'Remote Services: DCOM', 1, 'Di chuyển ngang bằng DCOM.', 'DCOM Execution'),
('T1021.006', 'Remote Services: Windows Remote Management', 1, 'Di chuyển ngang bằng PSRemote/WinRM.', 'WinRM PSRemote Execution'),
('T1134.005', 'Access Token Manipulation: SID-History Injection', 1, 'Tiêm nhiễm thuộc tính SID History.', 'Identity Injection'),
('T1558', 'Steal or Forge Kerberos Tickets', 0, 'Lạm dụng các cấu hình ủy quyền delegation.', 'Kerberos Delegation Abuse'),
('T1558.003', 'Steal or Forge Kerberos Tickets: Kerberoasting', 1, 'Lấy vé dịch vụ SPN để bẻ khóa offline.', 'Kerberoasting Attack'),
('T1552.004', 'Unsecured Credentials: Private Keys / Attributes', 1, 'Đọc mật khẩu thô lưu trong các thuộc tính AD.', 'Attributes Secrets Read'),
('T1003', 'OS Credential Dumping', 0, 'Trích xuất thông tin xác thực từ LSASS/sMSA.', 'Credentials Harvesting'),
('T1003.006', 'OS Credential Dumping: DCSync', 1, 'Giả mạo DC để đồng bộ bẻ khóa mật khẩu.', 'DCSync Replication'),
('T1078.002', 'Valid Accounts: Domain Accounts', 1, 'Sử dụng tài khoản domain hợp lệ để đăng nhập.', 'Valid Account Logons'),
('T1556', 'Modify Authentication Process', 0, 'Đăng ký Shadow Credentials khóa bất đối xứng.', 'Modify Auth Process'),
('T1484.001', 'Domain or Tenant Policy Modification: Group Policy Modification', 1, 'Sửa đổi liên kết GPO.', 'GPO Modification'),
('T1187', 'Forced Authentication', 0, 'Cưỡng ép nạn nhân tự động xác thực ngược lại.', 'Coerced Authentication'),
('T1649', 'Steal or Forge Authentication Certificates', 0, 'Lạm dụng cấu hình CA template để xin cấp chứng chỉ.', 'ADCS Enrollment'),
-- Vá bug: kỹ thuật mới cho các quan hệ cấu trúc AD tĩnh (MemberOf, Contains, GPLink, DCFor).
-- Đây không phải hành động chủ động của kẻ tấn công nên gần như không sinh sự kiện audit.
('T1069.002', 'Permission Groups Discovery: Domain Groups', 1, 'Quan hệ cấu trúc AD tĩnh: thành viên group, container, liên kết GPO, vai trò Domain Controller.', 'AD Structural Relationship');




INSERT INTO privilege_technique (privilege_id, technique_id) VALUES
((SELECT id FROM privilege WHERE privilege_name='ForceChangePassword'), 'T1098'),
((SELECT id FROM privilege WHERE privilege_name='CanRDP'), 'T1021.001'),
((SELECT id FROM privilege WHERE privilege_name='AddMember'), 'T1098'),
((SELECT id FROM privilege WHERE privilege_name='GenericAll'), 'T1098'),
((SELECT id FROM privilege WHERE privilege_name='AllowedToAct'), 'T1558'),
((SELECT id FROM privilege WHERE privilege_name='HasSIDHistory'), 'T1134.005'),
((SELECT id FROM privilege WHERE privilege_name='GenericWrite'), 'T1098'),
((SELECT id FROM privilege WHERE privilege_name='WriteDacl'), 'T1098'),
((SELECT id FROM privilege WHERE privilege_name='WriteOwner'), 'T1098'),
((SELECT id FROM privilege WHERE privilege_name='WriteSPN'), 'T1098'),
((SELECT id FROM privilege WHERE privilege_name='WriteSPN'), 'T1558.003'),
((SELECT id FROM privilege WHERE privilege_name='ReadLAPSPassword'), 'T1552.004'),
((SELECT id FROM privilege WHERE privilege_name='ReadGMSAPassword'), 'T1552.004'),
((SELECT id FROM privilege WHERE privilege_name='CanPSRemote'), 'T1021.006'),
((SELECT id FROM privilege WHERE privilege_name='ExecuteDCOM'), 'T1021.003'),
((SELECT id FROM privilege WHERE privilege_name='AddSelf'), 'T1098'),
((SELECT id FROM privilege WHERE privilege_name='WriteAccountRestrictions'), 'T1098'),
((SELECT id FROM privilege WHERE privilege_name='AddAllowedToAct'), 'T1098'),
((SELECT id FROM privilege WHERE privilege_name='AllowedToDelegate'), 'T1558'),
((SELECT id FROM privilege WHERE privilege_name='AbuseTGTDelegation'), 'T1558'),
((SELECT id FROM privilege WHERE privilege_name='SpoofSIDHistory'), 'T1134.005'),
((SELECT id FROM privilege WHERE privilege_name='DumpSMSAPassword'), 'T1003'),
((SELECT id FROM privilege WHERE privilege_name='AdminTo'), 'T1078.002'),
((SELECT id FROM privilege WHERE privilege_name='AllExtendedRights'), 'T1098'),
((SELECT id FROM privilege WHERE privilege_name='Owns'), 'T1098'),
((SELECT id FROM privilege WHERE privilege_name='SQLAdmin'), 'T1078.002'),
((SELECT id FROM privilege WHERE privilege_name='AddKeyCredentialLink'), 'T1556'),
((SELECT id FROM privilege WHERE privilege_name='WriteGPLink'), 'T1484.001'),
((SELECT id FROM privilege WHERE privilege_name='RemoteInteractiveLogonRight'), 'T1078.002'),
((SELECT id FROM privilege WHERE privilege_name='HasSession'), 'T1003'),
((SELECT id FROM privilege WHERE privilege_name='DCSync'), 'T1003.006'),
((SELECT id FROM privilege WHERE privilege_name='CoerceToTGT'), 'T1187'),
((SELECT id FROM privilege WHERE privilege_name='ADCSESC1'), 'T1649'),
((SELECT id FROM privilege WHERE privilege_name='ADCSESC3'), 'T1649'),
((SELECT id FROM privilege WHERE privilege_name='ADCSESC4'), 'T1649'),
((SELECT id FROM privilege WHERE privilege_name='ADCSESC6a'), 'T1649'),
((SELECT id FROM privilege WHERE privilege_name='ADCSESC6b'), 'T1649'),
((SELECT id FROM privilege WHERE privilege_name='ADCSESC9a'), 'T1649'),
((SELECT id FROM privilege WHERE privilege_name='ADCSESC9b'), 'T1649'),
((SELECT id FROM privilege WHERE privilege_name='ADCSESC10a'), 'T1649'),
((SELECT id FROM privilege WHERE privilege_name='ADCSESC10b'), 'T1649'),
((SELECT id FROM privilege WHERE privilege_name='ADCSESC13'), 'T1649'),
((SELECT id FROM privilege WHERE privilege_name='MemberOf'), 'T1069.002'),
((SELECT id FROM privilege WHERE privilege_name='Contains'), 'T1069.002'),
((SELECT id FROM privilege WHERE privilege_name='GPLink'), 'T1069.002'),
((SELECT id FROM privilege WHERE privilege_name='DCFor'), 'T1069.002');





INSERT INTO event_log (event_id, event_name, audit_score, sensor_score) VALUES
('4724', 'Password Reset Attempt', 2.0, 2.5),
('4624', 'Successful Logon', 2.0, 2.5),
('4728', 'Global Group Modification', 2.0, 2.5),
('5136', 'AD Directory Service Changes', 1.0, 2.5),
('4662', 'AD Object Access Operation', 1.0, 2.5),
('4769', 'Kerberos Ticket Request', 2.0, 2.5),
('4765', 'SID History Injected', 2.0, 2.5),
('4104', 'PowerShell Script block', 2.0, 2.5),
('4886', 'ADCS Certificate Request', 1.0, 1.0),
('4887', 'ADCS Certificate Issuance', 1.0, 1.0),
-- Vá bug: quan hệ cấu trúc AD tĩnh (không phải một hành động) hầu như không được audit
('NOEVENT', 'Không phát sinh sự kiện (quan hệ cấu trúc tĩnh)', 0.5, 2.0);






INSERT INTO detection_filter (filter_id, filter_field, filter_value, description) VALUES
('FILTER_GENERIC', 'winlog.event_data.AccessMask', 'Default', 'Không cần bộ lọc đặc hiệu / Lọc theo Event thô'),
('MASK_RESET_PWD', 'winlog.event_data.AccessMask', '0x10', 'Reset mật khẩu tài khoản'),
('LOGON_RDP', 'winlog.logon.type', '10', 'Logon Type 10 - Remote Interactive'),
('MASK_ADD_MEMBER', 'winlog.event_data.AccessMask', '0x1', 'Thêm thành viên vào group AD'),
('MASK_WRITE_DACL', 'winlog.event_data.AccessMask', '0x40000', 'Ghi đè hoặc sửa đổi DACL (WRITE_DAC)'),
('MASK_WRITE_OWNER', 'winlog.event_data.AccessMask', '0x80000', 'Thay đổi chủ sở hữu đối tượng (WRITE_OWNER)'),
('MASK_WRITE_PROP', 'winlog.event_data.AccessMask', '0x20', 'Ghi thuộc tính đối tượng (Write Property)'),
('MASK_READ_LAPS', 'winlog.event_data.Properties', '612cb747-c0e8-4f92-9221-fdd5f15b550d', 'Đọc thuộc tính LAPS ms-Mcs-AdmPwd'),
('MASK_READ_GMSA', 'winlog.event_data.Properties', 'b8dfa744-31dc-4ef1-ac7c-84baf7ef9da7', 'Đọc thuộc tính gMSA msDS-ManagedPassword'),
('LOGON_WINRM', 'winlog.logon.type', '3', 'Logon Type 3 - Network Logon (WinRM Execution)'),
('LOGON_DCOM', 'winlog.logon.type', '3', 'Logon Type 3 - Network Logon (DCOM Execution)'),
('SCRIPT_MIMIKATZ', 'powershell.file.script_block_text', 'sekurlsa::logonpasswords', 'Script chứa chuỗi dump mật khẩu Mimikatz'),
('MASK_SHADOW_CREDS', 'winlog.event_data.Properties', '5f202020-2020-2020-2020-202020202020', 'Sửa đổi thuộc tính msDS-KeyCredentialLink'),
('MASK_DCSYNC', 'winlog.event_data.AccessMask', '0x100', 'Yêu cầu đồng bộ hóa thư mục Directory Replication'),
('ADCS_TEMPLATE_ESC', 'winlog.event_data.CertificateTemplate', 'ESC_Template_Name', 'Yêu cầu cấp chứng chỉ có Template nhạy cảm'),
('FILTER_STRUCTURAL', 'n/a', 'static_relationship', 'Không có điều kiện lọc, quan hệ cấu trúc AD tĩnh không bị giám sát chủ động');





INSERT INTO technique_detection (technique_id, event_id, filter_id, fidelity_score) VALUES
('T1098', '4724', 'MASK_RESET_PWD', 4.0),       -- Reset Password (V=4, A=2, S=2.5) -> Cost = 20.0
('T1021.001', '4624', 'LOGON_RDP', 1.0),        -- CanRDP (V=1, A=2, S=2.5) -> Cost = 5.0
('T1098', '4728', 'MASK_ADD_MEMBER', 4.0),       -- AddMember/AddSelf (V=4, A=2, S=2.5) -> Cost = 20.0
('T1098', '5136', 'MASK_WRITE_DACL', 2.0),       -- Sửa DACL (V=2, A=1, S=2.5) -> Cost = 5.0
('T1098', '5136', 'MASK_WRITE_OWNER', 2.0),      -- Sửa Owner (V=2, A=1, S=2.5) -> Cost = 5.0
('T1098', '5136', 'MASK_WRITE_PROP', 2.0),       -- Sửa SPN / Account Rest. (V=2, A=1, S=2.5) -> Cost = 5.0
('T1558.003', '4769', 'FILTER_GENERIC', 1.0),    -- Kerberoasting (V=1, A=2, S=2.5) -> Cost = 5.0
('T1552.004', '4662', 'MASK_READ_LAPS', 3.0),    -- Đọc LAPS (V=3, A=1, S=2.5) -> Cost = 7.5
('T1552.004', '4662', 'MASK_READ_GMSA', 3.0),    -- Đọc gMSA (V=3, A=1, S=2.5) -> Cost = 7.5
('T1021.006', '4624', 'LOGON_WINRM', 1.0),       -- CanPSRemote WinRM (V=1, A=2, S=2.5) -> Cost = 5.0
('T1021.003', '4624', 'LOGON_DCOM', 1.0),        -- ExecuteDCOM (V=1, A=2, S=2.5) -> Cost = 5.0
('T1558', '4769', 'FILTER_GENERIC', 2.0),        -- Delegation Abuse (V=2, A=2, S=2.5) -> Cost = 10.0
('T1134.005', '4765', 'FILTER_GENERIC', 4.0),    -- SID History Injection (V=4, A=2, S=2.5) -> Cost = 20.0
('T1003', '4104', 'SCRIPT_MIMIKATZ', 3.0),       -- SMSA dumping / HasSession (V=3, A=2, S=2.5) -> Cost = 15.0
('T1078.002', '4624', 'FILTER_GENERIC', 1.0),    -- AdminTo / SQLAdmin (V=1, A=2, S=2.5) -> Cost = 5.0
('T1556', '5136', 'MASK_SHADOW_CREDS', 3.0),     -- Shadow Credentials (V=3, A=1, S=2.5) -> Cost = 7.5
('T1484.001', '5136', 'MASK_WRITE_PROP', 2.0),   -- WriteGPLink GPO (V=2, A=1, S=2.5) -> Cost = 5.0
('T1003.006', '4662', 'MASK_DCSYNC', 4.0),       -- DCSync (V=4, A=2, S=2.5) -> Cost = 20.0
('T1187', '4624', 'FILTER_GENERIC', 3.0),        -- CoerceToTGT (V=3, A=2, S=2.5) -> Cost = 15.0
('T1649', '4886', 'ADCS_TEMPLATE_ESC', 2.0),     -- ADCS Template (V=2, A=1, S=1) -> Cost = 2.0
('T1069.002', 'NOEVENT', 'FILTER_STRUCTURAL', 1.0);  -- MemberOf/Contains/GPLink/DCFor (V=1, A=0.5, S=2.0) -> Cost = 1.0

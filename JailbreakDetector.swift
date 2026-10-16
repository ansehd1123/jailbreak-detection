import SwiftUI
import Foundation
import Network
import Darwin
import MachO

@main
struct JailbreakApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}

struct ContentView: View {
    @State private var resultText: String = "Select a diagnostic check option below."
    @State private var resultColor: Color = .primary
    
    var body: some View {
        VStack(spacing: 15) {
            Text("Advanced Jailbreak Inspector")
                .font(.title2)
                .fontWeight(.bold)
                .multilineTextAlignment(.center)
                .padding(.top, 15)
            
            // 요구사항에 맞춘 메뉴 순서 배치 (1~5번 개별 진단, 6번 전체 진단)
            ScrollView {
                VStack(spacing: 10) {
                    MenuButton(title: "1. File-based Checks", color: .blue) {
                        runSpecificCheck(.fileBased)
                    }
                    MenuButton(title: "2. Checking File Permissions", color: .blue) {
                        runSpecificCheck(.filePermissions)
                    }
                    MenuButton(title: "3. Checking Protocol Handlers", color: .blue) {
                        runSpecificCheck(.protocolHandlers)
                    }
                    MenuButton(title: "4. Calling System APIs", color: .blue) {
                        runSpecificCheck(.systemAPIs)
                    }
                    MenuButton(title: "5. OpenSSH service Detection", color: .blue) {
                        runSpecificCheck(.openSSH)
                    }
                    MenuButton(title: "6. Run All Checks (Batch)", color: .purple) {
                        runSpecificCheck(.all)
                    }
                }
                .padding(.horizontal, 20)
            }
            .frame(maxHeight: 280)
            
            // 상세 탐지 사유 출력 영역
            ScrollView {
                Text(resultText)
                    .font(.system(.body, design: .monospaced))
                    .foregroundColor(resultColor)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding()
            }
            .background(Color(UIColor.secondarySystemBackground))
            .cornerRadius(10)
            .padding(.horizontal, 20)
            .padding(.bottom, 20)
        }
    }
    
    enum CheckType {
        case fileBased, filePermissions, protocolHandlers, systemAPIs, openSSH, all
    }
    
    private func runSpecificCheck(_ type: CheckType) {
        resultText = "Executing selected diagnostic check...\n\n"
        resultColor = .primary
        
        let core = JailbreakCore.shared
        var triggeredVectors: [String] = []
        let checkName: String
        
        switch type {
        case .fileBased:
            checkName = "1. File-based Checks"
            triggeredVectors = core.checkFileBased()
        case .filePermissions:
            checkName = "2. Checking File Permissions"
            triggeredVectors = core.checkFilePermissions()
        case .protocolHandlers:
            checkName = "3. Checking Protocol Handlers"
            triggeredVectors = core.checkProtocolHandlers()
        case .systemAPIs:
            checkName = "4. Calling System APIs"
            triggeredVectors = core.checkCallingSystemAPIs()
        case .openSSH:
            checkName = "5. OpenSSH service Detection"
            triggeredVectors = core.checkOpenSSHService()
        case .all:
            checkName = "6. Run All Checks (Batch)"
            triggeredVectors = core.runAllChecks()
        }
        
        displayResult(isJailbroken: !triggeredVectors.isEmpty, vectors: triggeredVectors, title: checkName)
    }
    
    private func displayResult(isJailbroken: Bool, vectors: [String], title: String) {
        var log = "=== [ \(title) ] Result ===\n\n"
        
        if isJailbroken {
            log += "⚠️ Status: JAILBROKEN (Threat Detected)\n\n"
            log += "Detailed Detection Reasons (Why):\n"
            for (index, vector) in vectors.enumerated() {
                log += "\(index + 1). \(vector)\n"
            }
            resultColor = .red
        } else {
            log += "✅ Status: Clean\n\n"
            log += "No security indicators or unauthorized artifacts found for this check."
            resultColor = .green
        }
        
        resultText = log
    }
}

struct MenuButton: View {
    let title: String
    let color: Color
    let action: () -> Void
    
    var body: some View {
        Button(action: action) {
            Text(title)
                .font(.headline)
                .foregroundColor(.white)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 10)
                .background(color)
                .cornerRadius(8)
        }
    }
}

// MARK: - Jailbreak Detection Core Logic (Detailed Evidence Reporting)
class JailbreakCore {
    static let shared = JailbreakCore()
    private init() {}

    func runAllChecks() -> [String] {
        var vectors: [String] = []
        vectors.append(contentsOf: checkFileBased())
        vectors.append(contentsOf: checkFilePermissions())
        vectors.append(contentsOf: checkProtocolHandlers())
        vectors.append(contentsOf: checkCallingSystemAPIs())
        vectors.append(contentsOf: checkOpenSSHService())
        return vectors
    }

    // 1. 파일 기반 체크 (File-based Checks) - 구체적인 경로 명시
    func checkFileBased() -> [String] {
        var triggered: [String] = []
        let paths = [
            "/Applications/Cydia.app",
            "/Applications/Sileo.app",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/bin/bash",
            "/usr/sbin/sshd",
            "/var/jb/usr/bin/bash",
            "/var/jb/Applications/Sileo.app",
            "/etc/apt"
        ]
        for path in paths {
            if FileManager.default.fileExists(atPath: path) || access(path, F_OK) == 0 {
                triggered.append("File Exists Found: [Path: \(path)] matched via fileManager/access API")
            }
        }
        return triggered
    }

    // 2. 파일 권한 기반 체크 (Checking File Permissions) - 권한 및 샌드박스 탈출 여부
    func checkFilePermissions() -> [String] {
        var triggered: [String] = []
        
        // 샌드박스 내부 앱이 시스템 영역이나 비정상적인 위치에 파일을 생성할 수 있는지 검사
        let testPath = "/private/jailbreak_permission_test_\(UUID().uuidString)"
        let isWritable = FileManager.default.createFile(atPath: testPath, contents: Data("test".utf8), attributes: nil)
        if isWritable {
            try? FileManager.default.removeItem(atPath: testPath)
            triggered.append("Permission Violation: Sandbox escaped; successfully created file in restricted path [Path: \(testPath)]")
        }
        
        // 심볼릭 링크 권한 구조 검사 (/var/jb Rootless 루트 체크)
        var s = stat()
        if lstat("/var/jb", &s) == 0 {
            if (s.st_mode & S_IFMT) == S_IFLNK {
                triggered.append("Symlink Permission Check: /var/jb is verified as a symbolic link (Rootless Jailbreak Indicator)")
            }
        }
        return triggered
    }

    // 3. 프로토콜 핸들러 기반 체크 (Checking Protocol Handlers) - 응답하는 스킴 명시
    func checkProtocolHandlers() -> [String] {
        var triggered: [String] = []
        let schemes = ["cydia://", "sileo://", "zbra://", "filza://", "activator://"]
        for scheme in schemes {
            if let url = URL(string: scheme), UIApplication.shared.canOpenURL(url) {
                triggered.append("Protocol Handler Responded: App can open registered jailbreak scheme [Scheme: \(scheme)]")
            }
        }
        return triggered
    }

    // 4. 시스템 API 호출 기반 체크 (Calling System APIs) - 동적 라이브러리 및 API 후킹 탐지
    func checkCallingSystemAPIs() -> [String] {
        var triggered: [String] = []
        
        // _dyld_get_image_name 시스템 API를 호출하여 메모리에 로드된 이미지 검사
        let keywords = ["substrate", "substitute", "hook", "frida", "roothide", "tweaks", "ellekit", "cydia"]
        let imageCount = _dyld_image_count()
        for i in 0..<imageCount {
            if let cStringName = _dyld_get_image_name(i) {
                let imageName = String(cString: cStringName).lowercased()
                for keyword in keywords {
                    if imageName.contains(keyword) {
                        triggered.append("System API Call (_dyld_get_image_name): Loaded library path contains hook keyword [Keyword: '\(keyword)'] in [Image: \(imageName)]")
                    }
                }
            }
        }
        return triggered
    }

    // 5. OpenSSH 서비스 기반 체크 (OpenSSH service Detection) - 활성화된 포트 번호 명시
    func checkOpenSSHService() -> [String] {
        var triggered: [String] = []
        let ports: [in_port_t] = [22, 44, 2222, 222]
        for port in ports {
            let sock = socket(AF_INET, SOCK_STREAM, 0)
            if sock < 0 { continue }
            var addr = sockaddr_in()
            addr.sin_len = __uint8_t(MemoryLayout<sockaddr_in>.size)
            addr.sin_family = sa_family_t(AF_INET)
            addr.sin_port = port.bigEndian
            addr.sin_addr.s_addr = inet_addr("127.0.0.1")
            let result = withUnsafePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(sock, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
            }
            close(sock)
            if result == 0 {
                triggered.append("Network Service Active: OpenSSH daemon is listening and accessible [Port: \(port)]")
            }
        }
        return triggered
    }
}

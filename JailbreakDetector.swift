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
    @State private var resultText: String = "Select a diagnostic check option below to view blacklist items and status."
    @State private var resultColor: Color = .primary
    
    var body: some View {
        VStack(spacing: 15) {
            Text("Advanced Jailbreak Inspector")
                .font(.title2)
                .fontWeight(.bold)
                .multilineTextAlignment(.center)
                .padding(.top, 15)
            
            // 진단 메뉴 버튼 영역 (요청하신 순서 및 6번 전체 체크)
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
            
            // 상세 진단 결과 및 블랙리스트 대조 리스트 출력 영역
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
    
    struct CheckItemResult {
        let name: String
        let isDetected: Bool
        let description: String
    }
    
    private func runSpecificCheck(_ type: CheckType) {
        resultText = "Analyzing system against criteria...\n"
        resultColor = .primary
        
        let core = JailbreakCore.shared
        var results: [CheckItemResult] = []
        let checkName: String
        
        switch type {
        case .fileBased:
            checkName = "1. File-based Checks"
            results = core.checkFileBased()
        case .filePermissions:
            checkName = "2. Checking File Permissions"
            results = core.checkFilePermissions()
        case .protocolHandlers:
            checkName = "3. Checking Protocol Handlers"
            results = core.checkProtocolHandlers()
        case .systemAPIs:
            checkName = "4. Calling System APIs"
            results = core.checkCallingSystemAPIs()
        case .openSSH:
            checkName = "5. OpenSSH service Detection"
            results = core.checkOpenSSHService()
        case .all:
            checkName = "6. Run All Checks (Batch)"
            results = core.runAllChecks()
        }
        
        let hasThreat = results.contains { $0.isDetected }
        displayResult(isJailbroken: hasThreat, items: results, title: checkName)
    }
    
    private func displayResult(isJailbroken: Bool, items: [CheckItemResult], title: String) {
        var log = "[\(title)]\n\n"
        
        if isJailbroken {
            log += "⚠️ Status: JAILBROKEN (Threat Found)\n\n"
            resultColor = .red
        } else {
            log += "✅ Status: Clean (All Safe)\n\n"
            resultColor = .green
        }
        
        log += "Blacklist / Criteria Evaluation:\n"
        for item in items {
            let badge = item.isDetected ? "[⚠️ DETECTED]" : "[✅ CLEAN]"
            log += " \(badge) \(item.name)\n"
            if !item.description.isEmpty {
                log += "    └─ \(item.description)\n"
            }
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

// MARK: - Jailbreak Detection Core Logic with Blacklist Criteria Return
class JailbreakCore {
    static let shared = JailbreakCore()
    private init() {}

    func runAllChecks() -> [ContentView.CheckItemResult] {
        var allItems: [ContentView.CheckItemResult] = []
        allItems.append(contentsOf: checkFileBased())
        allItems.append(contentsOf: checkFilePermissions())
        allItems.append(contentsOf: checkProtocolHandlers())
        allItems.append(contentsOf: checkCallingSystemAPIs())
        allItems.append(contentsOf: checkOpenSSHService())
        return allItems
    }

    // 1. 파일 기반 체크 (블랙리스트 경로 대조)
    func checkFileBased() -> [ContentView.CheckItemResult] {
        var results: [ContentView.CheckItemResult] = []
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
            let exists = FileManager.default.fileExists(atPath: path) || access(path, F_OK) == 0
            results.append(ContentView.CheckItemResult(
                name: path,
                isDetected: exists,
                description: exists ? "Blacklist artifact found on disk" : "Not found"
            ))
        }
        return results
    }

    // 2. 파일 권한 및 샌드박스 체크 (행위 기반 블랙리스트)
    func checkFilePermissions() -> [ContentView.CheckItemResult] {
        var results: [ContentView.CheckItemResult] = []
        
        // 샌드박스 탈출 쓰기 테스트
        let testPath = "/private/jb_test_\(UUID().uuidString.prefix(6))"
        let isWritable = FileManager.default.createFile(atPath: testPath, contents: Data("test".utf8), attributes: nil)
        if isWritable {
            try? FileManager.default.removeItem(atPath: testPath)
        }
        results.append(ContentView.CheckItemResult(
            name: "Sandbox Write Escape Test",
            isDetected: isWritable,
            description: isWritable ? "Successfully wrote to restricted private path" : "Blocked by sandbox (Normal)"
        ))
        
        // 루트리스 심볼릭 링크 체크
        var s = stat()
        let isSymlink = (lstat("/var/jb", &s) == 0) && ((s.st_mode & S_IFMT) == S_IFLNK)
        results.append(ContentView.CheckItemResult(
            name: "Symlink Check (/var/jb)",
            isDetected: isSymlink,
            description: isSymlink ? "/var/jb is a symbolic link (Rootless jailbreak)" : "Clean or does not exist"
        ))
        
        return results
    }

    // 3. 프로토콜 핸들러 체크 (URL 스킴 블랙리스트 대조)
    func checkProtocolHandlers() -> [ContentView.CheckItemResult] {
        var results: [ContentView.CheckItemResult] = []
        let schemes = ["cydia://", "sileo://", "zbra://", "filza://", "activator://"]
        
        for scheme in schemes {
            let canOpen = if let url = URL(string: scheme) { UIApplication.shared.canOpenURL(url) } else { false }
            results.append(ContentView.CheckItemResult(
                name: scheme,
                isDetected: canOpen,
                description: canOpen ? "Registered app responded to URL scheme" : "Not registered"
            ))
        }
        return results
    }

    // 4. 시스템 API / 동적 라이브러리 후킹 키워드 블랙리스트 대조
    func checkCallingSystemAPIs() -> [ContentView.CheckItemResult] {
        var results: [ContentView.CheckItemResult] = []
        let keywords = ["substrate", "substitute", "hook", "frida", "roothide", "tweaks", "ellekit", "cydia"]
        
        // 메모리에 로드된 전체 이미지 수집
        var foundKeywords: Set<String> = []
        let imageCount = _dyld_image_count()
        for i in 0..<imageCount {
            if let cStringName = _dyld_get_image_name(i) {
                let imageName = String(cString: cStringName).lowercased()
                for keyword in keywords {
                    if imageName.contains(keyword) {
                        foundKeywords.insert(keyword)
                    }
                }
            }
        }
        
        for keyword in keywords {
            let matched = foundKeywords.contains(keyword)
            results.append(ContentView.CheckItemResult(
                name: "Keyword: [\(keyword)]",
                isDetected: matched,
                description: matched ? "Matched inside loaded dynamic libraries" : "Not detected in memory"
            ))
        }
        return results
    }

    // 5. OpenSSH 서비스 포트 블랙리스트 대조
    func checkOpenSSHService() -> [ContentView.CheckItemResult] {
        var results: [ContentView.CheckItemResult] = []
        let ports: [in_port_t] = [22, 44, 2222, 222]
        
        for port in ports {
            let sock = socket(AF_INET, SOCK_STREAM, 0)
            var isOpen = false
            if sock >= 0 {
                var addr = sockaddr_in()
                addr.sin_len = __uint8_t(MemoryLayout<sockaddr_in>.size)
                addr.sin_family = sa_family_t(AF_INET)
                addr.sin_port = port.bigEndian
                addr.sin_addr.s_addr = inet_addr("127.0.0.1")
                let connectResult = withUnsafePointer(to: &addr) {
                    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(sock, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
                }
                close(sock)
                isOpen = (connectResult == 0)
            }
            
            results.append(ContentView.CheckItemResult(
                name: "Port \(port)",
                isDetected: isOpen,
                description: isOpen ? "Daemon service is listening locally" : "Port closed / unreachable"
            ))
        }
        return results
    }
}

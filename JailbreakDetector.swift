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
            
            // 진단 메뉴 버튼 영역
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
            
            // 단순하고 직관적인 결과 출력 영역
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
        resultText = "Scanning system...\n"
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
        var log = "[\(title)]\n\n"
        
        if isJailbroken {
            log += "⚠️ Status: JAILBROKEN\n\n"
            log += "Detected Items:\n"
            for (index, vector) in vectors.enumerated() {
                log += " • \(vector)\n"
            }
            resultColor = .red
        } else {
            log += "✅ Status: Clean\n\n"
            log += "No security threats found."
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

// MARK: - Jailbreak Detection Core Logic (Simplified & Clean Output)
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
                triggered.append("File: \(path)")
            }
        }
        return triggered
    }

    func checkFilePermissions() -> [String] {
        var triggered: [String] = []
        let testPath = "/private/jb_test_\(UUID().uuidString.prefix(6))"
        if FileManager.default.createFile(atPath: testPath, contents: Data("test".utf8), attributes: nil) {
            try? FileManager.default.removeItem(atPath: testPath)
            triggered.append("Sandbox Escape (Writable Path)")
        }
        
        var s = stat()
        if lstat("/var/jb", &s) == 0 {
            if (s.st_mode & S_IFMT) == S_IFLNK {
                triggered.append("Symlink: /var/jb (Rootless)")
            }
        }
        return triggered
    }

    func checkProtocolHandlers() -> [String] {
        var triggered: [String] = []
        let schemes = ["cydia://", "sileo://", "zbra://", "filza://", "activator://"]
        for scheme in schemes {
            if let url = URL(string: scheme), UIApplication.shared.canOpenURL(url) {
                triggered.append("Scheme: \(scheme)")
            }
        }
        return triggered
    }

    func checkCallingSystemAPIs() -> [String] {
        var triggered: [String] = []
        let keywords = ["substrate", "substitute", "hook", "frida", "roothide", "tweaks", "ellekit", "cydia"]
        let imageCount = _dyld_image_count()
        for i in 0..<imageCount {
            if let cStringName = _dyld_get_image_name(i) {
                let imageName = String(cString: cStringName).lowercased()
                for keyword in keywords {
                    if imageName.contains(keyword) {
                        triggered.append("Hook Library: \(keyword)")
                    }
                }
            }
        }
        // 중복 제거 (동일 키워드 여러 개 매칭 방지)
        return Array(Set(triggered))
    }

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
                triggered.append("OpenSSH Port: \(port)")
            }
        }
        return triggered
    }
}

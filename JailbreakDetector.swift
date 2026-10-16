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
        VStack(spacing: 20) {
            Text("Advanced Jailbreak Inspector")
                .font(.title2)
                .fontWeight(.bold)
                .multilineTextAlignment(.center)
                .padding(.top, 20)
            
            // 메뉴별 개별 검사 버튼 영역
            ScrollView {
                VStack(spacing: 10) {
                    MenuButton(title: "1. Run All Checks (Batch)", color: .purple) {
                        runSpecificCheck(.all)
                    }
                    MenuButton(title: "2. Check File-Based Artifacts", color: .blue) {
                        runSpecificCheck(.fileBased)
                    }
                    MenuButton(title: "3. Check URL Schemes", color: .blue) {
                        runSpecificCheck(.protocolHandlers)
                    }
                    MenuButton(title: "4. Check OpenSSH Services", color: .blue) {
                        runSpecificCheck(.openSSH)
                    }
                    MenuButton(title: "5. Check DYLD Images (Hooks)", color: .blue) {
                        runSpecificCheck(.dyldImages)
                    }
                    MenuButton(title: "6. Check Symbolic Links (/var/jb)", color: .blue) {
                        runSpecificCheck(.symlinks)
                    }
                }
                .padding(.horizontal, 20)
            }
            .frame(maxHeight: 260)
            
            // 결과 출력 영역
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
        case all, fileBased, protocolHandlers, openSSH, dyldImages, symlinks
    }
    
    private func runSpecificCheck(_ type: CheckType) {
        resultText = "Executing selected diagnostic check...\n\n"
        resultColor = .primary
        
        let core = JailbreakCore.shared
        var triggeredVectors: [String] = []
        let checkName: String
        
        switch type {
        case .all:
            let result = core.runAllChecks()
            displayResult(isJailbroken: result.isJailbroken, vectors: result.triggeredVectors, title: "All Checks Combined")
            return
        case .fileBased:
            checkName = "File-Based Artifacts Check"
            if core.checkFileBased() { triggeredVectors.append("File System: Jailbreak files/paths detected") }
        case .protocolHandlers:
            checkName = "URL Schemes Check"
            if core.checkProtocolHandlers() { triggeredVectors.append("URL Scheme: Jailbreak app schemes responded") }
        case .openSSH:
            checkName = "OpenSSH Service Check"
            if core.checkOpenSSHService() { triggeredVectors.append("Network: OpenSSH ports (22/44/2222) active") }
        case .dyldImages:
            checkName = "DYLD Loaded Images Check"
            if core.checkDyldImages() { triggeredVectors.append("Memory: Hooking framework libraries loaded") }
        case .symlinks:
            checkName = "Symbolic Links Check"
            if core.checkSymlinks() { triggeredVectors.append("File System: Abnormal symbolic link (/var/jb) detected") }
        }
        
        displayResult(isJailbroken: !triggeredVectors.isEmpty, vectors: triggeredVectors, title: checkName)
    }
    
    private func displayResult(isJailbroken: Bool, vectors: [String], title: String) {
        var log = "=== [ \(title) ] Result ===\n\n"
        
        if isJailbroken {
            log += "⚠️ Status: JAILBROKEN\n\n"
            log += "Triggered Vectors:\n"
            for (index, vector) in vectors.enumerated() {
                log += "\(index + 1). \(vector)\n"
            }
            resultColor = .red
        } else {
            log += "✅ Status: Clean\n\n"
            log += "No security indicators found for this check."
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

// MARK: - Jailbreak Detection Core Logic (Modularized & English Strings)
class JailbreakCore {
    static let shared = JailbreakCore()
    private init() {}

    func runAllChecks() -> (isJailbroken: Bool, triggeredVectors: [String]) {
        var vectors: [String] = []
        if checkFileBased() { vectors.append("File System: Jailbreak files/paths detected") }
        if checkProtocolHandlers() { vectors.append("URL Scheme: Jailbreak app schemes responded") }
        if checkOpenSSHService() { vectors.append("Network: OpenSSH ports (22/44/2222) active") }
        if checkDyldImages() { vectors.append("Memory: Hooking framework libraries loaded") }
        if checkSymlinks() { vectors.append("File System: Abnormal symbolic link (/var/jb) detected") }
        return (isJailbroken: !vectors.isEmpty, triggeredVectors: vectors)
    }

    func checkFileBased() -> Bool {
        let paths = [
            "/Applications/Cydia.app",
            "/Applications/Sileo.app",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/bin/bash",
            "/usr/sbin/sshd",
            "/var/jb/usr/bin/bash",
            "/var/jb/Applications/Sileo.app"
        ]
        for path in paths {
            if FileManager.default.fileExists(atPath: path) || access(path, F_OK) == 0 { return true }
        }
        return false
    }

    func checkProtocolHandlers() -> Bool {
        let schemes = ["cydia://", "sileo://", "zbra://", "filza://"]
        for scheme in schemes {
            if let url = URL(string: scheme), UIApplication.shared.canOpenURL(url) { return true }
        }
        return false
    }

    func checkOpenSSHService() -> Bool {
        let ports: [in_port_t] = [22, 44, 2222]
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
            if result == 0 { return true }
        }
        return false
    }

    func checkDyldImages() -> Bool {
        let keywords = ["substrate", "substitute", "hook", "frida", "roothide", "tweaks", "ellekit"]
        let imageCount = _dyld_image_count()
        for i in 0..<imageCount {
            if let cStringName = _dyld_get_image_name(i) {
                let imageName = String(cString: cStringName).lowercased()
                for keyword in keywords { if imageName.contains(keyword) { return true } }
            }
        }
        return false
    }

    func checkSymlinks() -> Bool {
        var s = stat()
        if lstat("/var/jb", &s) == 0 {
            if (s.st_mode & S_IFMT) == S_IFLNK { return true }
        }
        return false
    }
}

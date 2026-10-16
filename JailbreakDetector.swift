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
    @State private var resultText: String = "버튼을 눌러 탈옥 검사를 시작하세요."
    @State private var resultColor: Color = .primary
    
    var body: some View {
        VStack(spacing: 30) {
            Text("Advanced Jailbreak Detector")
                .font(.title2)
                .fontWeight(.bold)
                .multilineTextAlignment(.center)
                .padding(.top, 40)
            
            Button(action: runScan) {
                Text("Run Deep Scan")
                    .font(.headline)
                    .foregroundColor(.white)
                    .frame(maxWidth: .infinity)
                    .padding()
                    .background(Color.blue)
                    .cornerRadius(10)
            }
            .padding(.horizontal, 30)
            
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
    
    private func runScan() {
        resultText = "시스템 환경을 정밀 진단 중입니다...\n\n"
        resultColor = .primary
        
        let scanResult = JailbreakCore.shared.runAllChecks()
        var log = "=== 진단 완료 ===\n\n"
        
        if scanResult.isJailbroken {
            log += "⚠️ 상태: 탈옥 감지됨 (JAILBROKEN)\n\n"
            log += "탐지된 항목:\n"
            for (index, vector) in scanResult.triggeredVectors.enumerated() {
                log += "\(index + 1). \(vector)\n"
            }
            resultColor = .red
        } else {
            log += "✅ 상태: 안전함 (Clean)\n\n"
            log += "탈옥 흔적이 발견되지 않았습니다."
            resultColor = .green
        }
        
        resultText = log
    }
}

// MARK: - 탈옥 탐지 코어 로직
struct JailbreakCheckResult {
    let isJailbroken: Bool
    let triggeredVectors: [String]
}

class JailbreakCore {
    static let shared = JailbreakCore()
    private init() {}

    func runAllChecks() -> JailbreakCheckResult {
        var vectors: [String] = []
        if checkFileBased() { vectors.append("파일 시스템: 탈옥 관련 파일/경로 감지") }
        if checkProtocolHandlers() { vectors.append("URL Scheme: 탈옥 앱 스킴 응답 감지") }
        if checkOpenSSHService() { vectors.append("네트워크: OpenSSH 포트(22/44/2222) 활성화 감지") }
        if checkDyldImages() { vectors.append("메모리: 후킹 프레임워크 라이브러리 로드 감지") }
        if checkSymlinks() { vectors.append("파일 시스템: 비정상적인 심볼릭 링크(/var/jb) 감지") }
        return JailbreakCheckResult(isJailbroken: !vectors.isEmpty, triggeredVectors: vectors)
    }

    private func checkFileBased() -> Bool {
        let paths = ["/Applications/Cydia.app", "/Applications/Sileo.app", "/Library/MobileSubstrate/MobileSubstrate.dylib", "/bin/bash", "/usr/sbin/sshd", "/var/jb/usr/bin/bash", "/var/jb/Applications/Sileo.app"]
        for path in paths {
            if FileManager.default.fileExists(atPath: path) || access(path, F_OK) == 0 { return true }
        }
        return false
    }

    private func checkProtocolHandlers() -> Bool {
        let schemes = ["cydia://", "sileo://", "zbra://", "filza://"]
        for scheme in schemes {
            if let url = URL(string: scheme), UIApplication.shared.canOpenURL(url) { return true }
        }
        return false
    }

    private func checkOpenSSHService() -> Bool {
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

    private func checkDyldImages() -> Bool {
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

    private func checkSymlinks() -> Bool {
        var s = stat()
        if lstat("/var/jb", &s) == 0 { if (s.st_mode & S_IFMT) == S_IFLNK { return true } }
        return false
    }
}

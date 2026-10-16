import SwiftUI

struct ContentView: View {
    // 진단 검사 유형을 정의하는 열거형(Enum)
    enum CheckType {
        case fileBased
        case sshCheck
        case sandboxCheck
        case fullCheck
    }

    @State private var resultText: String = "Select a diagnostic check option below to view blacklist items and status."
    @State private var resultColor: Color = .primary

    var body: some View {
        NavigationView {
            VStack(spacing: 20) {
                // 메뉴 섹션 뷰 호출 및 콜백 핸들링
                MenuSectionView { checkType in
                    executeDiagnosticCheck(for: checkType)
                }
                
                // 결과 출력 영역
                ScrollView {
                    Text(resultText)
                        .font(.system(.body, design: .monospaced))
                        .foregroundColor(resultColor)
                        .padding()
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .background(Color(.systemGray6))
                .cornerRadius(8)
                .padding()
                
                Spacer()
            }
            .navigationTitle("Jailbreak Detector")
        }
    }

    /// 선택된 탈옥 진단 항목에 따른 실제 진단 로직 실행
    private func executeDiagnosticCheck(for type: CheckType) {
        switch type {
        case .fileBased:
            runFileBasedChecks()
        case .sshCheck:
            runSSHChecks()
        case .sandboxCheck:
            runSandboxChecks()
        case .fullCheck:
            runFullChecks()
        }
    }

    /// 1. 파일 기반 탈옥 검사 (Cydia, MobileSubstrate, 주요 탈옥 경로)
    private func runFileBasedChecks() {
        let suspiciousPaths = [
            "/Applications/Cydia.app",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/bin/bash",
            "/etc/apt",
            "/private/var/lib/apt/",
            "/var/lib/cydia",
            "/private/var/lib/cydia",
            "/private/var/mobile/Library/SBSettings/Themes"
        ]
        
        var detectedItems: [String] = []
        for path in suspiciousPaths {
            if FileManager.default.fileExists(atPath: path) {
                detectedItems.append(path)
            }
        }
        
        if detectedItems.isEmpty {
            resultText = "[*] File-based Checks Completed.\n- Status: Clean (No known jailbreak files found)."
            resultColor = .green
        } else {
            resultText = "[!] Jailbreak Detected (File-based)!\n- Detected items:\n" + detectedItems.map { "  • \($0)" }.joined(separator: "\n")
            resultColor = .red
        }
    }

    /// 2. SSH 및 데몬 검사
    private func runSSHChecks() {
        let sshPaths = [
            "/usr/sbin/sshd",
            "/usr/bin/ssh",
            "/usr/libexec/ssh-keysign",
            "/etc/ssh/sshd_config"
        ]
        
        var detectedItems: [String] = []
        for path in sshPaths {
            if FileManager.default.fileExists(atPath: path) {
                detectedItems.append(path)
            }
        }
        
        if detectedItems.isEmpty {
            resultText = "[*] SSH & Daemon Check Completed.\n- Status: Clean (No unauthorized SSH binaries found)."
            resultColor = .green
        } else {
            resultText = "[!] SSH / Daemon Detected!\n- Detected items:\n" + detectedItems.map { "  • \($0)" }.joined(separator: "\n")
            resultColor = .red
        }
    }

    /// 3. 샌드박스 무결성 검사 (컨테이너 외곽 쓰기 권한 테스트)
    private func runSandboxChecks() {
        let sandboxPath = "/private/jailbreak_test.txt"
        do {
            try "test_content".write(toFile: sandboxPath, atomically: true, encoding: .utf8)
            try? FileManager.default.removeItem(atPath: sandboxPath)
            resultText = "[!] Sandbox Integrity Compromised!\n- Status: Able to write outside sandbox container (/private/)."
            resultColor = .red
        } catch {
            resultText = "[*] Sandbox Integrity Check Completed.\n- Status: Intact (Sandbox write restriction enforced)."
            resultColor = .green
        }
    }

    /// 4. 전체 확인 (Full Check - 모든 진단 항목 통합 실행)
    private func runFullChecks() {
        var report = "[*] Executing Full Diagnostic Check...\n\n"
        
        // 파일 및 바이너리 검사
        let filePaths = [
            "/Applications/Cydia.app",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/bin/bash",
            "/etc/apt",
            "/private/var/lib/apt/"
        ]
        let foundFiles = filePaths.filter { FileManager.default.fileExists(atPath: $0) }
        
        report += "1. File Checks: " + (foundFiles.isEmpty ? "Clean" : "Detected (\(foundFiles.count))") + "\n"
        for p in foundFiles { report += "   - [!] \(p)\n" }
        
        // SSH 검사
        let sshPaths = ["/usr/sbin/sshd", "/usr/bin/ssh"]
        let foundSSH = sshPaths.filter { FileManager.default.fileExists(atPath: $0) }
        
        report += "2. SSH Check: " + (foundSSH.isEmpty ? "Clean" : "Detected (\(foundSSH.count))") + "\n"
        for p in foundSSH { report += "   - [!] \(p)\n" }
        
        // 샌드박스 검사
        let sandboxPath = "/private/jailbreak_test.txt"
        let canWriteOutside = (try? "test".write(toFile: sandboxPath, atomically: true, encoding: .utf8)) != nil
        if canWriteOutside { try? FileManager.default.removeItem(atPath: sandboxPath) }
        
        report += "3. Sandbox Check: " + (canWriteOutside ? "Compromised" : "Intact") + "\n"
        
        let isJailbroken = !foundFiles.isEmpty || !foundSSH.isEmpty || canWriteOutside
        report += "\n----------------------------------------\n"
        report += isJailbroken ? "[!] Result: Device is JAILBROKEN" : "[*] Result: Device appears secure"
        
        resultText = report
        resultColor = isJailbroken ? .red : .green
    }
}

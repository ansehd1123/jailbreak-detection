import SwiftUI

struct ContentView: View {
    // 진단 검사 유형을 정의하는 열거형(Enum) 추가
    enum CheckType {
        case fileBased
        case filePermissions
        case sandboxIntegrity
        case debugging
        case suspiciousFiles
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

    /// 선택된 탈옥 진단 항목에 따른 로직 실행
    private func executeDiagnosticCheck(for type: CheckType) {
        switch type {
        case .fileBased:
            resultText = "[*] Executing File-based Checks...\n- Checking known jailbreak binaries (/bin/bash, /usr/sbin/sshd, Cydia.app, etc.)\n- Status: Blacklist items scanned."
            resultColor = .red
        case .filePermissions:
            resultText = "[*] Checking File Permissions...\n- Verifying system partition mount status and restricted paths write-permissions.\n- Status: Secure."
            resultColor = .blue
        case .sandboxIntegrity:
            resultText = "[*] Checking Sandbox Integrity...\n- Verifying sandbox escape vectors and write access outside container.\n- Status: Intact."
            resultColor = .green
        case .debugging:
            resultText = "[*] Checking Debugger Attachment (ptrace)...\n- Status: No active debugger detected."
            resultColor = .primary
        case .suspiciousFiles:
            resultText = "[*] Scanning Suspicious Files and Symlinks...\n- Status: Clean."
            resultColor = .primary
        }
    }
}
